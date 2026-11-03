/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#if defined(__OpenBSD__)
#include <netinet/ip_carp.h>
#elif defined(__FreeBSD__)
#include <net/if_vlan_var.h>
#elif defined(__NetBSD__)
#include <net/if_ether.h>	/* ETHER_ADDR_LEN, used by if_vlanvar.h */
#include <net/if_vlanvar.h>
#endif
#endif

#include "neighbot.h"
#include "capture.h"
#include "db.h"
#include "log.h"

struct subnet {
	char    iface[32];
	int     af;
	uint8_t addr[16];
	uint8_t mask[16];
};

static struct subnet subnets[MAX_SUBNETS];
static int subnet_count;

struct local_ip {
	char    iface[32];
	int     af;
	uint8_t ip[16];
};

static struct local_ip own_ips[MAX_LOCAL_IPS];
static int own_ip_count;

struct learned_subnet {
	char    iface[32];
	int     af;
	uint8_t addr[16];
	uint8_t mask[16];
	time_t  expires;
};

static struct learned_subnet learned[MAX_LEARNED_SUBNETS];
static int learned_count;

/* the monitored interfaces, for refreshes triggered by the parser */
static struct iface *mon_ifaces;
static int mon_count;

static void
prefix_to_mask(int af, int prefix_len, uint8_t *mask)
{
	int alen = ip_len(af);
	int bits = prefix_len;

	memset(mask, 0, 16);
	for (int i = 0; i < alen && bits > 0; i++) {
		if (bits >= 8) {
			mask[i] = 0xff;
			bits -= 8;
		} else {
			mask[i] = (uint8_t)(0xff << (8 - bits));
			bits = 0;
		}
	}
}

/* Whether mask covers the whole address: a /32 or /128 host address. */
static int
is_host_mask(int af, const uint8_t *mask)
{
	int alen = ip_len(af);

	for (int i = 0; i < alen; i++) {
		if (mask[i] != 0xff)
			return 0;
	}
	return 1;
}

/* Whether ip is in the network addr/mask. */
static int
net_match(int af, const uint8_t *ip, const uint8_t *addr,
          const uint8_t *mask)
{
	int alen = ip_len(af);

	for (int j = 0; j < alen; j++) {
		if ((ip[j] & mask[j]) != (addr[j] & mask[j]))
			return 0;
	}
	return 1;
}

int
capture_add_learned_subnet(const char *iface, int af,
                           const uint8_t *addr, int prefix_len,
                           uint32_t lifetime_sec, int keep_longer)
{
	int alen = ip_len(af);
	uint8_t mask[16];
	uint8_t netaddr[16];
	time_t now = mono_now();
	time_t exp;
	int oldest = -1;
	time_t oldest_exp = 0;
	int slot;

	if (prefix_len < 0 || prefix_len > alen * 8)
		return -1;

	prefix_to_mask(af, prefix_len, mask);

	memset(netaddr, 0, sizeof(netaddr));
	for (int i = 0; i < alen; i++)
		netaddr[i] = addr[i] & mask[i];

	if (lifetime_sec == 0) {
		/* a zero valid lifetime withdraws the prefix: expire any
		 * matching learned entry now so bogon detection resumes */
		for (int i = 0; i < learned_count; i++) {
			struct learned_subnet *s = &learned[i];

			if (s->af == af && strcmp(s->iface, iface) == 0 &&
			    memcmp(s->addr, netaddr, alen) == 0 &&
			    memcmp(s->mask, mask, alen) == 0 &&
			    s->expires > now) {
				s->expires = now;
				return 2;
			}
		}
		return -1;
	}
	if (lifetime_sec > LEARNED_MAX_LIFETIME)
		lifetime_sec = LEARNED_MAX_LIFETIME;
	exp = now + (time_t)lifetime_sec;

	/* refresh a live entry, or re-learn one whose slot has lapsed
	 * (expired or withdrawn) so the not-local to local transition is
	 * surfaced again with a fresh notification */
	for (int i = 0; i < learned_count; i++) {
		struct learned_subnet *s = &learned[i];

		if (s->af == af && strcmp(s->iface, iface) == 0 &&
		    memcmp(s->addr, netaddr, alen) == 0 &&
		    memcmp(s->mask, mask, alen) == 0) {
			int lapsed = (s->expires <= now);

			if (lapsed || !keep_longer || exp > s->expires)
				s->expires = exp;
			return lapsed ? 1 : 0;
		}
	}

	/* prefer an expired slot */
	for (int i = 0; i < learned_count; i++) {
		if (learned[i].expires <= now) {
			slot = i;
			goto fill;
		}
	}

	if (learned_count < MAX_LEARNED_SUBNETS) {
		slot = learned_count++;
		goto fill;
	}

	/* evict the slot closest to expiry */
	for (int i = 0; i < learned_count; i++) {
		if (oldest < 0 || learned[i].expires < oldest_exp) {
			oldest = i;
			oldest_exp = learned[i].expires;
		}
	}
	slot = oldest;

fill:
	{
		struct learned_subnet *s = &learned[slot];

		snprintf(s->iface, sizeof(s->iface), "%s", iface);
		s->af = af;
		memset(s->addr, 0, sizeof(s->addr));
		memset(s->mask, 0, sizeof(s->mask));
		memcpy(s->addr, netaddr, alen);
		memcpy(s->mask, mask, alen);
		s->expires = exp;
	}
	return 1;
}

/* Forget the prefixes learned on iface, no longer monitored, so that
 * they do not count as local to a monitored interface any more. */
void
capture_forget_learned(const char *iface)
{
	for (int i = 0; i < learned_count; i++) {
		if (strcmp(learned[i].iface, iface) == 0)
			learned[i].expires = 0;
	}
}

void
capture_reset_learned_subnets(void)
{
	learned_count = 0;
	memset(learned, 0, sizeof(learned));
}

static void
fill_local_macs(struct iface *ifaces, int count)
{
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) < 0) {
		log_err("getifaddrs: %s", strerror(errno));
		return;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

#if defined(__linux__)
		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;
		struct sockaddr_ll *sll =
		    (struct sockaddr_ll *)ifa->ifa_addr;
		if (sll->sll_halen != 6)
			continue;
		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				memcpy(ifaces[i].local_mac,
				    sll->sll_addr, 6);
				break;
			}
		}
#else
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		struct sockaddr_dl *sdl =
		    (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen != 6)
			continue;
		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				memcpy(ifaces[i].local_mac,
				    LLADDR(sdl), 6);
				break;
			}
		}
#endif
	}

	freeifaddrs(ifap);
}

static void
fill_local_subnets(struct iface *ifaces, int count)
{
	struct ifaddrs *ifap, *ifa;
	static int full_warned;

	/* keep the current table if the addresses cannot be read */
	if (getifaddrs(&ifap) < 0) {
		log_err("getifaddrs: %s", strerror(errno));
		return;
	}
	subnet_count = 0;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		int af;
		const uint8_t *addr, *mask;
		int found = 0;

		if (!ifa->ifa_addr || !ifa->ifa_netmask)
			continue;

		af = ifa->ifa_addr->sa_family;
		if (af == AF_INET) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)ifa->ifa_addr;
			struct sockaddr_in *sinm =
			    (struct sockaddr_in *)ifa->ifa_netmask;
			addr = (const uint8_t *)&sin->sin_addr;
			mask = (const uint8_t *)&sinm->sin_addr;
		} else if (af == AF_INET6) {
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6 *)ifa->ifa_addr;
			struct sockaddr_in6 *sin6m =
			    (struct sockaddr_in6 *)ifa->ifa_netmask;
			addr = (const uint8_t *)&sin6->sin6_addr;
			mask = (const uint8_t *)&sin6m->sin6_addr;
		} else {
			continue;
		}

		/* skip link-local subnets: link-local sources are accepted
		 * before any subnet check, so such an entry never matches and
		 * would only make an interface with no other address look as
		 * if it had a configured subnet */
		if ((af == AF_INET && IS_LINKLOCAL4(addr)) ||
		    (af == AF_INET6 && IS_LINKLOCAL6(addr)))
			continue;

		/* only track subnets for monitored interfaces */
		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				found = 1;
				break;
			}
		}
		if (!found)
			continue;

		if (subnet_count >= MAX_SUBNETS) {
			if (!full_warned)
				log_msg("subnet table full (%d), some local "
				    "subnets not tracked", MAX_SUBNETS);
			full_warned = 1;
			break;
		}

		capture_add_subnet(ifa->ifa_name, af, addr, mask);
	}

	freeifaddrs(ifap);
}

void
capture_add_subnet(const char *iface, int af,
                   const uint8_t *addr, const uint8_t *mask)
{
	int alen = ip_len(af);
	struct subnet *s;

	if (subnet_count >= MAX_SUBNETS)
		return;

	s = &subnets[subnet_count];
	snprintf(s->iface, sizeof(s->iface), "%s", iface);
	s->af = af;
	memset(s->addr, 0, sizeof(s->addr));
	memset(s->mask, 0, sizeof(s->mask));
	memcpy(s->addr, addr, alen);
	memcpy(s->mask, mask, alen);
	subnet_count++;
}

void
capture_reset_subnets(void)
{
	subnet_count = 0;
}

static void
fill_local_ips(struct iface *ifaces, int count)
{
	struct ifaddrs *ifap, *ifa;
	static int full_warned;

	/* keep the current table if the addresses cannot be read */
	if (getifaddrs(&ifap) < 0) {
		log_err("getifaddrs: %s", strerror(errno));
		return;
	}
	own_ip_count = 0;

	/* IPv6 link-local addresses go in first: probes are sent from
	 * them, and getifaddrs() may list hundreds of IPv4 addresses
	 * before any IPv6 one */
	for (int pass = 0; pass < 2; pass++) {
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			int af, ll;
			const uint8_t *addr;
			int found = 0;

			if (!ifa->ifa_addr)
				continue;

			af = ifa->ifa_addr->sa_family;
			if (af == AF_INET) {
				struct sockaddr_in *sin =
				    (struct sockaddr_in *)ifa->ifa_addr;
				addr = (const uint8_t *)&sin->sin_addr;
			} else if (af == AF_INET6) {
				struct sockaddr_in6 *sin6 =
				    (struct sockaddr_in6 *)ifa->ifa_addr;
				addr = (const uint8_t *)&sin6->sin6_addr;
			} else {
				continue;
			}
			ll = (af == AF_INET6 && IS_LINKLOCAL6(addr));
			if (ll != (pass == 0))
				continue;

			for (int i = 0; i < count; i++) {
				if (strcmp(ifaces[i].name,
				    ifa->ifa_name) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				continue;

			if (own_ip_count >= MAX_LOCAL_IPS) {
				if (!full_warned)
					log_msg("local IP table full (%d), "
					    "some own IPs not tracked",
					    MAX_LOCAL_IPS);
				full_warned = 1;
				break;
			}

			capture_add_own_ip(ifa->ifa_name, af, addr);
		}
	}

	freeifaddrs(ifap);
}

void
capture_add_own_ip(const char *iface, int af, const uint8_t *ip)
{
	int alen = ip_len(af);
	struct local_ip *l;

	if (own_ip_count >= MAX_LOCAL_IPS)
		return;

	l = &own_ips[own_ip_count];
	snprintf(l->iface, sizeof(l->iface), "%s", iface);
	l->af = af;
	memset(l->ip, 0, sizeof(l->ip));
	memcpy(l->ip, ip, alen);
	/* KAME stacks (OpenBSD, NetBSD) return link-local addresses from
	 * getifaddrs() with the scope id embedded in bytes 2-3; those bytes
	 * are zero on the wire, so clear them to compare with packets */
	if (af == AF_INET6 && IS_LINKLOCAL6(l->ip))
		l->ip[2] = l->ip[3] = 0;
	own_ip_count++;
}

/*
 * Pick the source address for a probe of target on iface: for IPv4 an
 * address of iface, preferably in the target's subnet; for IPv6 the
 * link-local address of iface. Returns 0 and fills src with zeros when
 * iface has no such address.
 */
int
capture_probe_src(const char *iface, int af, const uint8_t *target,
                  uint8_t *src)
{
	int alen = ip_len(af);
	int found = 0;

	memset(src, 0, 16);
	if (af == AF_INET) {
		for (int i = 0; i < subnet_count; i++) {
			struct subnet *s = &subnets[i];
			int match;

			if (s->af != AF_INET || strcmp(s->iface, iface) != 0)
				continue;
			match = net_match(af, target, s->addr, s->mask);
			if (match || !found) {
				memcpy(src, s->addr, alen);
				found = 1;
			}
			if (match)
				break;
		}
		return found;
	}

	for (int i = 0; i < own_ip_count; i++) {
		struct local_ip *l = &own_ips[i];

		if (l->af == AF_INET6 && strcmp(l->iface, iface) == 0 &&
		    IS_LINKLOCAL6(l->ip)) {
			memcpy(src, l->ip, alen);
			return 1;
		}
	}
	return 0;
}

void
capture_reset_own_ips(void)
{
	own_ip_count = 0;
}

int
capture_is_own_ip(int af, const uint8_t *ip)
{
	int alen = ip_len(af);

	for (int i = 0; i < own_ip_count; i++) {
		if (own_ips[i].af == af &&
		    memcmp(own_ips[i].ip, ip, alen) == 0)
			return 1;
	}
	return 0;
}

/*
 * Whether ip is local to iface, or to any monitored interface when iface
 * is NULL: link-local, or inside a configured or learned subnet. With no
 * subnet known for the address family, locality cannot be determined and
 * every address counts as local. A /32 or /128 address, as DHCPv6 leases
 * and point-to-point style setups use, says nothing about which neighbours
 * are on-link: it matches itself but does not count as a known subnet.
 */
static int
is_local(const char *iface, int af, const uint8_t *ip)
{
	int has_subnet = 0;
	time_t now = mono_now();

	/* link-local addresses are always valid on the local link */
	if (af == AF_INET6 && IS_LINKLOCAL6(ip))
		return 1;
	if (af == AF_INET && IS_LINKLOCAL4(ip))
		return 1;

	for (int i = 0; i < subnet_count; i++) {
		struct subnet *s = &subnets[i];

		if (s->af != af || (iface && strcmp(s->iface, iface) != 0))
			continue;
		if (net_match(af, ip, s->addr, s->mask))
			return 1;
		if (!is_host_mask(af, s->mask))
			has_subnet = 1;
	}

	for (int i = 0; i < learned_count; i++) {
		struct learned_subnet *s = &learned[i];

		if (s->af != af || s->expires <= now ||
		    (iface && strcmp(s->iface, iface) != 0))
			continue;
		if (net_match(af, ip, s->addr, s->mask))
			return 1;
		if (!is_host_mask(af, s->mask))
			has_subnet = 1;
	}

	return !has_subnet;
}

/* Whether ip is the broadcast address of an IPv4 subnet of iface, which
 * hosts keep a fixed entry for. A /31 or /32 has none. */
int
capture_is_bcast(const char *iface, const uint8_t *ip)
{
	for (int i = 0; i < subnet_count; i++) {
		struct subnet *s = &subnets[i];
		int j;

		if (s->af != AF_INET || strcmp(s->iface, iface) != 0 ||
		    (s->mask[3] & 0x03) != 0)
			continue;
		for (j = 0; j < 4; j++) {
			if ((ip[j] & s->mask[j]) != (s->addr[j] & s->mask[j]) ||
			    (ip[j] | s->mask[j]) != 0xff)
				break;
		}
		if (j == 4)
			return 1;
	}
	return 0;
}

/* Whether prefix/prefix_len lies inside a subnet configured on iface, or
 * is a /64 or longer holding a /128 address of iface, as the on-link
 * prefix of a DHCPv6 lease does. A shorter prefix around an address is
 * not, so that a rogue RA making a whole site on-link is still mailed. */
int
capture_prefix_configured(const char *iface, int af, const uint8_t *prefix,
                          int prefix_len)
{
	int alen = ip_len(af);
	uint8_t mask[16];

	prefix_to_mask(af, prefix_len, mask);
	for (int i = 0; i < subnet_count; i++) {
		struct subnet *s = &subnets[i];
		int bits = 0;

		if (s->af != af || strcmp(s->iface, iface) != 0)
			continue;
		if (is_host_mask(af, s->mask)) {
			if (prefix_len >= 64 &&
			    net_match(af, s->addr, prefix, mask))
				return 1;
			continue;
		}
		for (int j = 0; j < alen; j++)
			for (uint8_t m = s->mask[j]; m; m <<= 1)
				bits++;
		if (prefix_len >= bits &&
		    net_match(af, prefix, s->addr, s->mask))
			return 1;
	}
	return 0;
}

#if defined(__linux__)
#define ROUTE_LOOKUPS_MAX 64	/* route lookups a second */

/*
 * The interface through which the host reaches ip without a gateway,
 * written into name, as with a route added by "ip route add
 * 198.51.100.0/24 dev eth0" and no address of the host in it: hosts
 * resolve and cache such neighbours like those of a subnet. Returns 0
 * when there is none. The kernel is asked for the route to ip alone, as
 * "ip route get" does, which costs the same however large the routing
 * table is; its reply is queued before send() returns, so it is read
 * without waiting. The last answer serves the second question about the
 * same address, and past ROUTE_LOOKUPS_MAX lookups in a second an
 * address counts as foreign, so a flood of foreign addresses cannot keep
 * the daemon busy asking.
 */
static int
onlink_oif(int af, const uint8_t *ip, char name[IF_NAMESIZE])
{
	static struct {
		time_t  when;
		int     af;
		uint8_t ip[16];
		char    oif[IF_NAMESIZE];
	} last;
	static time_t budget_start;
	static int budget;
	struct {
		struct nlmsghdr nh;
		struct rtmsg    rt;
		struct rtattr   rta;
		uint8_t         dst[16];
	} req;
	union {
		struct nlmsghdr nh;
		char            buf[4096];
	} resp;
	const struct rtmsg *rt;
	const struct rtattr *rta;
	time_t now = mono_now();
	int alen = ip_len(af), oif = 0, gateway = 0, attrlen, s;
	ssize_t len;

	if (last.when == now && last.af == af &&
	    memcmp(last.ip, ip, alen) == 0) {
		memcpy(name, last.oif, IF_NAMESIZE);
		return name[0] != '\0';
	}
	if (budget_start != now) {
		budget_start = now;
		budget = 0;
	}
	if (budget >= ROUTE_LOOKUPS_MAX)
		return 0;
	budget++;
	name[0] = '\0';

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rt) + RTA_LENGTH(alen));
	req.nh.nlmsg_type = RTM_GETROUTE;
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.rt.rtm_family = (unsigned char)af;
	req.rt.rtm_dst_len = (unsigned char)(alen * 8);
	req.rta.rta_type = RTA_DST;
	req.rta.rta_len = RTA_LENGTH(alen);
	memcpy(req.dst, ip, alen);

	s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (s < 0)
		return 0;
	if (send(s, &req, req.nh.nlmsg_len, 0) < 0) {
		close(s);
		return 0;
	}
	len = recv(s, &resp, sizeof(resp), MSG_DONTWAIT);
	close(s);

	/* an error, such as no route at all, is an NLMSG_ERROR reply */
	if (len >= 0 && NLMSG_OK(&resp.nh, (unsigned)len) &&
	    resp.nh.nlmsg_type == RTM_NEWROUTE &&
	    resp.nh.nlmsg_len >= NLMSG_LENGTH(sizeof(*rt))) {
		rt = NLMSG_DATA(&resp.nh);
		attrlen = (int)RTM_PAYLOAD(&resp.nh);
		for (rta = RTM_RTA(rt); RTA_OK(rta, attrlen);
		    rta = RTA_NEXT(rta, attrlen)) {
			if (rta->rta_type == RTA_GATEWAY ||
			    rta->rta_type == RTA_VIA)
				gateway = 1;
			else if (rta->rta_type == RTA_OIF &&
			    RTA_PAYLOAD(rta) >= sizeof(oif))
				memcpy(&oif, RTA_DATA(rta), sizeof(oif));
		}
		if (rt->rtm_type != RTN_UNICAST || gateway || oif <= 0 ||
		    if_indextoname((unsigned)oif, name) == NULL)
			name[0] = '\0';
	}

	last.when = now;
	last.af = af;
	memcpy(last.ip, ip, alen);
	memcpy(last.oif, name, IF_NAMESIZE);
	return name[0] != '\0';
}

/* Whether ip is reached on-link through iface, or through any monitored
 * interface when iface is NULL. */
static int
onlink_route(const char *iface, int af, const uint8_t *ip)
{
	char name[IF_NAMESIZE];

	if ((iface == NULL && mon_count == 0) || !onlink_oif(af, ip, name))
		return 0;
	if (iface != NULL)
		return strcmp(name, iface) == 0;
	for (int i = 0; i < mon_count; i++) {
		if (strcmp(mon_ifaces[i].name, name) == 0)
			return 1;
	}
	return 0;
}
#else
/* not looked up on the BSDs: only subnets and RA prefixes are local */
static int
onlink_route(const char *iface, int af, const uint8_t *ip)
{
	(void)iface; (void)af; (void)ip;
	return 0;
}
#endif

int
capture_is_local_any(int af, const uint8_t *ip)
{
	return is_local(NULL, af, ip) || onlink_route(NULL, af, ip);
}

int
capture_is_local(const char *iface, int af, const uint8_t *ip)
{
	return is_local(iface, af, ip);
}

/*
 * Whether iface exists, is up and has a carrier. An unknown link state
 * counts as up, and so does a failure to read the interface list.
 */
int
capture_link_up(const char *iface)
{
	struct ifaddrs *ifap, *ifa;
	int up = 0;

	if (getifaddrs(&ifap) < 0)
		return 1;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, iface) != 0)
			continue;
#if defined(__linux__)
		/* IFF_RUNNING reflects the carrier on Linux */
		up = (ifa->ifa_flags & (IFF_UP | IFF_RUNNING)) ==
		    (IFF_UP | IFF_RUNNING);
#else
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		up = (ifa->ifa_flags & IFF_UP) != 0;
		if (up && ifa->ifa_data != NULL)
			up = ((struct if_data *)ifa->ifa_data)->ifi_link_state !=
			    LINK_STATE_DOWN;
#endif
		break;
	}
	freeifaddrs(ifap);
	return up;
}

/*
 * capture_is_local(), but before calling an address foreign re-read the
 * interface addresses, at most once a second: an address added since the
 * last periodic refresh would otherwise make its neighbours, and the
 * host itself, look like bogons. Then ask the kernel whether it reaches
 * the address on-link anyway.
 */
int
capture_is_local_fresh(const char *iface, int af, const uint8_t *ip)
{
	static time_t last;
	time_t now;

	if (capture_is_local(iface, af, ip))
		return 1;
	now = mono_now();
	if (mon_ifaces != NULL && now != last) {
		last = now;
		capture_refresh_addrs(mon_ifaces, mon_count);
		if (capture_is_local(iface, af, ip))
			return 1;
	}
	return onlink_route(iface, af, ip);
}

static int
is_vlan_parent(const char *name, char parents[][32], int count)
{
	for (int i = 0; i < count; i++) {
		if (strcmp(name, parents[i]) == 0)
			return 1;
	}
	return 0;
}

#if defined(__linux__)
int
capture_parse_vlan_parents(const char *path,
    char parents[][32], int max)
{
	FILE *f;
	char line[256];
	int count = 0;

	f = fopen(path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f) && count < max) {
		char dev[32], parent[32];
		int vid;

		if (sscanf(line, "%31s | %d | %31s",
		    dev, &vid, parent) != 3)
			continue;

		/* deduplicate */
		if (!is_vlan_parent(parent, parents, count)) {
			snprintf(parents[count], 32, "%s", parent);
			count++;
		}
	}

	fclose(f);
	return count;
}
#endif

static int
find_vlan_parents(const pcap_if_t *alldevs, char parents[][32], int max)
{
#if defined(__linux__)
	(void)alldevs;
	return capture_parse_vlan_parents("/proc/net/vlan/config",
	    parents, max);
#elif defined(__OpenBSD__)
	const pcap_if_t *dev;
	int sock, count = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return 0;

	for (dev = alldevs; dev && count < max; dev = dev->next) {
		struct if_parent ifp;

		/* only consider VLAN interfaces: vlan(4) and svlan(4) */
		if (strncmp(dev->name, "vlan", 4) != 0 &&
		    strncmp(dev->name, "svlan", 5) != 0)
			continue;

		memset(&ifp, 0, sizeof(ifp));
		snprintf(ifp.ifp_name, sizeof(ifp.ifp_name),
		    "%s", dev->name);
		if (ioctl(sock, SIOCGIFPARENT, &ifp) < 0)
			continue;
		if (ifp.ifp_parent[0] == '\0')
			continue;

		if (!is_vlan_parent(ifp.ifp_parent, parents, count)) {
			snprintf(parents[count], 32, "%s", ifp.ifp_parent);
			count++;
		}
	}

	close(sock);
	return count;
#elif defined(__FreeBSD__) || defined(__NetBSD__)
	const pcap_if_t *dev;
	int sock, count = 0;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return 0;

	for (dev = alldevs; dev && count < max; dev = dev->next) {
		struct ifreq ifr;
		struct vlanreq vreq;

		memset(&ifr, 0, sizeof(ifr));
		memset(&vreq, 0, sizeof(vreq));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),
		    "%s", dev->name);
		ifr.ifr_data = (caddr_t)&vreq;

		if (ioctl(sock, SIOCGETVLAN, &ifr) < 0)
			continue;
		if (vreq.vlr_parent[0] == '\0')
			continue;

		if (!is_vlan_parent(vreq.vlr_parent, parents, count)) {
			snprintf(parents[count], 32, "%s", vreq.vlr_parent);
			count++;
		}
	}

	close(sock);
	return count;
#else
	(void)alldevs;
	(void)parents;
	(void)max;
	return 0;
#endif
}

/*
 * Remove parents that have non-link-local IP addresses.
 * Those interfaces carry their own untagged traffic and must be monitored.
 */
static int
filter_assigned_parents(char parents[][32], int count)
{
	struct ifaddrs *ifap, *ifa;
	int assigned[64] = {0};
	int out = 0;

	if (count <= 0 || count > 64)
		return count;

	if (getifaddrs(&ifap) < 0) {
		log_err("getifaddrs: %s", strerror(errno));
		return count;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		const uint8_t *ip;

		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)ifa->ifa_addr;
			ip = (const uint8_t *)&sin->sin_addr;
			if (IS_LINKLOCAL4(ip))
				continue;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6 *)ifa->ifa_addr;
			ip = (const uint8_t *)&sin6->sin6_addr;
			if (IS_LINKLOCAL6(ip))
				continue;
		} else {
			continue;
		}

		for (int i = 0; i < count; i++) {
			if (strcmp(parents[i], ifa->ifa_name) == 0)
				assigned[i] = 1;
		}
	}

	freeifaddrs(ifap);

	for (int i = 0; i < count; i++) {
		if (!assigned[i]) {
			if (out != i)
				memcpy(parents[out], parents[i], 32);
			out++;
		}
	}
	return out;
}

#if defined(__linux__)
/* Whether /sys/class/net/<name>/<attr> exists. */
static int
sysfs_net_has(const char *name, const char *attr)
{
	char path[128];
	struct stat st;

	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", name, attr);
	return stat(path, &st) == 0;
}

/*
 * Whether name is a macvlan or macvtap device whose lower device is
 * known, written into lower. macvtap uses the macvlan driver.
 */
static int
macvlan_lower(const char *name, char lower[IF_NAMESIZE])
{
	struct ethtool_drvinfo info;
	struct ifreq ifr;
	char path[128], attr[IF_NAMESIZE + 6];
	FILE *f;
	int s, idx, found = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return 0;
	memset(&ifr, 0, sizeof(ifr));
	memset(&info, 0, sizeof(info));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	info.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (void *)&info;
	if (ioctl(s, SIOCETHTOOL, &ifr) == 0 &&
	    strncmp(info.driver, "macvlan", sizeof(info.driver)) == 0)
		found = 1;
	close(s);
	if (!found)
		return 0;

	/* iflink is the interface index of the lower device, but in the
	 * network namespace of that device: in a container it can name
	 * another interface, or this one. The kernel only links the lower
	 * device in sysfs when both share a namespace, so require it. */
	snprintf(path, sizeof(path), "/sys/class/net/%s/iflink", name);
	f = fopen(path, "r");
	if (f == NULL)
		return 0;
	found = fscanf(f, "%d", &idx) == 1 && idx > 0 &&
	    if_indextoname((unsigned)idx, lower) != NULL;
	fclose(f);
	if (!found)
		return 0;
	snprintf(attr, sizeof(attr), "lower_%s", lower);
	return sysfs_net_has(name, attr);
}
#endif

#if defined(__OpenBSD__)
/*
 * Whether name is a carp(4) interface, writing its parent into carpdev.
 * carp hands every multicast and broadcast frame of the parent to each
 * of its interfaces, whose capture sees it a second time.
 */
static int
carp_parent(const char *name, char carpdev[IFNAMSIZ])
{
	struct carpreq carpr;
	struct ifreq ifr;
	int s, found;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return 0;
	memset(&ifr, 0, sizeof(ifr));
	memset(&carpr, 0, sizeof(carpr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	ifr.ifr_data = (caddr_t)&carpr;
	found = ioctl(s, SIOCGVH, &ifr) == 0 && carpr.carpr_carpdev[0] != '\0';
	close(s);
	if (found)
		strlcpy(carpdev, carpr.carpr_carpdev, IFNAMSIZ);
	return found;
}
#endif

/*
 * The snap length for name: room for its MTU, the Ethernet header and
 * VLAN tags, as hosts take ARP and ND from any frame their interface
 * receives, and at least SNAP_MIN: a bridge or a VLAN interface also
 * receives frames as large as those of a port or parent with a larger
 * MTU. No more: the capture ring of Linux keeps a slot of that size for
 * every frame, so a larger one holds fewer frames.
 */
static int
snap_len(const char *name)
{
	struct ifreq ifr;
	int s, mtu = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
		if (ioctl(s, SIOCGIFMTU, &ifr) == 0)
			mtu = ifr.ifr_mtu;
		close(s);
	}
	if (mtu <= 0 || mtu > SNAP_LEN - SNAP_HDR)
		return SNAP_LEN;
	return mtu + SNAP_HDR > SNAP_MIN ? mtu + SNAP_HDR : SNAP_MIN;
}

int
capture_open_all(struct iface *ifaces, int max)
{
	pcap_if_t *alldevs, *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int count = 0;

	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		log_err("pcap_findalldevs: %s", errbuf);
		return -1;
	}

	char vlan_parents[64][32];
	int nparents = 0;
	if (!cfg.iface) {
		nparents = find_vlan_parents(alldevs, vlan_parents, 64);
		nparents = filter_assigned_parents(vlan_parents, nparents);
	}

	for (dev = alldevs; dev && count < max; dev = dev->next) {
		pcap_t *p;
		struct bpf_program bpf;
		int dlt, promisc;

		/* skip loopback */
		if (dev->flags & PCAP_IF_LOOPBACK)
			continue;

		/* skip capture sources that are not network interfaces
		 * (D-Bus, Bluetooth, USB, netfilter). Only Ethernet is kept,
		 * and opening the D-Bus one connects to the system bus as
		 * root, a connection libdbus keeps open after pcap_close()
		 * and the privilege drop. */
		if (if_nametoindex(dev->name) == 0)
			continue;

		/* skip VLAN trunk parents when monitoring all interfaces */
		if (nparents > 0 &&
		    is_vlan_parent(dev->name, vlan_parents, nparents)) {
			log_msg("skipping %s (has VLAN subinterfaces)",
			    dev->name);
			continue;
		}

#if defined(__linux__)
		/* When monitoring all interfaces, skip bridge ports and bond
		 * slaves: their frames reach the bridge or bond device, which
		 * is monitored, and capturing on both would report every
		 * station once per port, with probes sent on a port reaching
		 * only the hosts behind it. */
		if (!cfg.iface && (sysfs_net_has(dev->name, "brport") ||
		    sysfs_net_has(dev->name, "bonding_slave"))) {
			log_msg("skipping %s (bridge port or bond slave)",
			    dev->name);
			continue;
		}

		/* Skip macvlan and macvtap devices for the same reason: their
		 * lower device carries the frames they send and receive, even
		 * between two of them. Keep one whose lower device is a VLAN
		 * trunk skipped above, as it is then the only view of untagged
		 * traffic. Not ipvlan, which passes unicast between two of its
		 * devices without the lower device seeing it. */
		{
			char lower[IF_NAMESIZE];

			if (!cfg.iface && macvlan_lower(dev->name, lower) &&
			    !is_vlan_parent(lower, vlan_parents, nparents)) {
				log_msg("skipping %s (macvlan on %s)",
				    dev->name, lower);
				continue;
			}
		}
#elif defined(__OpenBSD__)
		/* When monitoring all interfaces, skip carp interfaces: their
		 * parent, which is monitored, carries all their frames, and
		 * capturing on both would report stations twice. Keep one
		 * whose parent is a VLAN trunk skipped above. */
		{
			char carpdev[IFNAMSIZ];

			if (!cfg.iface && carp_parent(dev->name, carpdev) &&
			    !is_vlan_parent(carpdev, vlan_parents, nparents)) {
				log_msg("skipping %s (carp on %s)", dev->name,
				    carpdev);
				continue;
			}
		}
#endif

		/* filter by interface name if specified */
		if (cfg.iface && strcmp(dev->name, cfg.iface) != 0)
			continue;

		/* the name is a field of the CSV database, which has no
		 * quoting; a comma in it would corrupt every saved row, and
		 * rows with non-printable bytes in it are rejected at load */
		if (strchr(dev->name, ',') != NULL || has_nonprint(dev->name)) {
			log_err("skipping interface with a comma or a "
			    "non-printable character in its name");
			continue;
		}

		p = pcap_create(dev->name, errbuf);
		if (!p) {
			log_err("pcap_create(%s): %s", dev->name, errbuf);
			continue;
		}

#if defined(__linux__)
		/* a bridge device only receives the unicast frames meant for
		 * the host; in promiscuous mode it also gets those forwarded
		 * between its ports, such as a spoofed ARP reply to one host */
		promisc = sysfs_net_has(dev->name, "bridge");
#else
		promisc = 0;
#endif
		/* immediate mode: deliver packets to poll() without
		 * waiting for BPF buffer timeout (needed on BSDs) */
		if (pcap_set_snaplen(p, snap_len(dev->name)) != 0 ||
		    pcap_set_promisc(p, promisc) != 0 ||
		    pcap_set_timeout(p, POLL_TIMEOUT_MS) != 0 ||
		    pcap_set_immediate_mode(p, 1) != 0) {
			log_err("pcap_set(%s): cannot set capture options",
			    dev->name);
			pcap_close(p);
			continue;
		}

		if (pcap_activate(p) < 0) {
			log_err("pcap_activate(%s): %s", dev->name,
			        pcap_geterr(p));
			pcap_close(p);
			continue;
		}

		/* only Ethernet interfaces */
		dlt = pcap_datalink(p);
		if (dlt != DLT_EN10MB) {
			pcap_close(p);
			continue;
		}

		if (pcap_compile(p, &bpf, BPF_FILTER, 1,
		                 PCAP_NETMASK_UNKNOWN) < 0) {
			log_err("pcap_compile(%s): %s", dev->name,
			        pcap_geterr(p));
			pcap_close(p);
			continue;
		}

		if (pcap_setfilter(p, &bpf) < 0) {
			log_err("pcap_setfilter(%s): %s", dev->name,
			        pcap_geterr(p));
			pcap_freecode(&bpf);
			pcap_close(p);
			continue;
		}

		pcap_freecode(&bpf);

		if (pcap_setnonblock(p, 1, errbuf) < 0) {
			log_err("pcap_setnonblock(%s): %s", dev->name, errbuf);
			pcap_close(p);
			continue;
		}

		int fd = pcap_get_selectable_fd(p);
		if (fd < 0) {
			log_err("pcap_get_selectable_fd(%s): not supported",
			        dev->name);
			pcap_close(p);
			continue;
		}

		/* keep the capture descriptor out of forked children
		 * (notifications, sendmail) so they never inherit BPF fds */
		if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
			log_err("fcntl(FD_CLOEXEC, %s): %s", dev->name,
			        strerror(errno));

		snprintf(ifaces[count].name, sizeof(ifaces[count].name),
		         "%s", dev->name);
		/* the interface pcap_activate() bound to, should the name
		 * have moved to another one since the check above */
		ifaces[count].index = if_nametoindex(dev->name);
		ifaces[count].handle = p;
		ifaces[count].fd = fd;
		memset(ifaces[count].local_mac, 0,
		    sizeof(ifaces[count].local_mac));

		log_msg("monitoring %s", dev->name);
		count++;
	}

	if (dev != NULL)
		log_msg("interface limit (%d) reached, remaining interfaces "
		    "not monitored", max);

	pcap_freealldevs(alldevs);
	mon_ifaces = ifaces;
	mon_count = count;
	capture_refresh_addrs(ifaces, count);
	return count;
}

/* Re-read the MACs, subnets and addresses of the monitored interfaces,
 * so changes made after startup (DHCP, SLAAC, renumbering, a new MAC
 * address) are taken into account; probes are built from these. */
void
capture_refresh_addrs(struct iface *ifaces, int count)
{
	fill_local_macs(ifaces, count);
	fill_local_subnets(ifaces, count);
	fill_local_ips(ifaces, count);
}

void
capture_close_all(struct iface *ifaces, int count)
{
	for (int i = 0; i < count; i++) {
		if (ifaces[i].handle) {
			pcap_close(ifaces[i].handle);
			ifaces[i].handle = NULL;
			ifaces[i].fd = -1;
		}
	}
}

