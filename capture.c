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

#include <ifaddrs.h>
#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <linux/if_packet.h>
#include <stdio.h>
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#if defined(__FreeBSD__)
#include <net/if_vlan_var.h>
#elif defined(__NetBSD__)
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

static int
learned_match(const struct learned_subnet *s, int af, const uint8_t *ip)
{
	int alen = ip_len(af);

	for (int j = 0; j < alen; j++) {
		if ((ip[j] & s->mask[j]) != (s->addr[j] & s->mask[j]))
			return 0;
	}
	return 1;
}

int
capture_add_learned_subnet(const char *iface, int af,
                           const uint8_t *addr, int prefix_len,
                           uint32_t lifetime_sec)
{
	int alen = ip_len(af);
	uint8_t mask[16];
	uint8_t netaddr[16];
	time_t now = time(NULL);
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

	if (lifetime_sec == 0)
		return -1;
	if (lifetime_sec > LEARNED_MAX_LIFETIME)
		lifetime_sec = LEARNED_MAX_LIFETIME;
	exp = now + (time_t)lifetime_sec;

	/* look for an existing matching entry to refresh */
	for (int i = 0; i < learned_count; i++) {
		struct learned_subnet *s = &learned[i];

		if (s->af == af && strcmp(s->iface, iface) == 0 &&
		    memcmp(s->addr, netaddr, alen) == 0 &&
		    memcmp(s->mask, mask, alen) == 0) {
			s->expires = exp;
			return 0;
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
	if (oldest < 0)
		return -1;
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

	if (getifaddrs(&ifap) < 0)
		return;

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

	subnet_count = 0;

	if (getifaddrs(&ifap) < 0)
		return;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		int af, alen;
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
			alen = 4;
		} else if (af == AF_INET6) {
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6 *)ifa->ifa_addr;
			struct sockaddr_in6 *sin6m =
			    (struct sockaddr_in6 *)ifa->ifa_netmask;
			addr = (const uint8_t *)&sin6->sin6_addr;
			mask = (const uint8_t *)&sin6m->sin6_addr;
			alen = 16;
		} else {
			continue;
		}

		/* only track subnets for monitored interfaces */
		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				found = 1;
				break;
			}
		}
		if (!found)
			continue;

		if (subnet_count >= MAX_SUBNETS)
			break;

		struct subnet *s = &subnets[subnet_count];
		snprintf(s->iface, sizeof(s->iface), "%s", ifa->ifa_name);
		s->af = af;
		memset(s->addr, 0, sizeof(s->addr));
		memset(s->mask, 0, sizeof(s->mask));
		memcpy(s->addr, addr, alen);
		memcpy(s->mask, mask, alen);
		subnet_count++;
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

	own_ip_count = 0;

	if (getifaddrs(&ifap) < 0)
		return;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		int af, alen;
		const uint8_t *addr;
		int found = 0;

		if (!ifa->ifa_addr)
			continue;

		af = ifa->ifa_addr->sa_family;
		if (af == AF_INET) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)ifa->ifa_addr;
			addr = (const uint8_t *)&sin->sin_addr;
			alen = 4;
		} else if (af == AF_INET6) {
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6 *)ifa->ifa_addr;
			addr = (const uint8_t *)&sin6->sin6_addr;
			alen = 16;
		} else {
			continue;
		}

		for (int i = 0; i < count; i++) {
			if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
				found = 1;
				break;
			}
		}
		if (!found)
			continue;

		if (own_ip_count >= MAX_LOCAL_IPS)
			break;

		struct local_ip *l = &own_ips[own_ip_count];
		l->af = af;
		memset(l->ip, 0, sizeof(l->ip));
		memcpy(l->ip, addr, alen);
		own_ip_count++;
	}

	freeifaddrs(ifap);
}

void
capture_add_own_ip(int af, const uint8_t *ip)
{
	int alen = ip_len(af);
	struct local_ip *l;

	if (own_ip_count >= MAX_LOCAL_IPS)
		return;

	l = &own_ips[own_ip_count];
	l->af = af;
	memset(l->ip, 0, sizeof(l->ip));
	memcpy(l->ip, ip, alen);
	own_ip_count++;
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

int
capture_is_local_any(int af, const uint8_t *ip)
{
	int alen = ip_len(af);
	int has_subnet = 0;
	time_t now = time(NULL);

	if (af == AF_INET6 && IS_LINKLOCAL6(ip))
		return 1;
	if (af == AF_INET && IS_LINKLOCAL4(ip))
		return 1;

	for (int i = 0; i < subnet_count; i++) {
		struct subnet *s = &subnets[i];

		if (s->af != af)
			continue;
		has_subnet = 1;

		int match = 1;
		for (int j = 0; j < alen; j++) {
			if ((ip[j] & s->mask[j]) !=
			    (s->addr[j] & s->mask[j])) {
				match = 0;
				break;
			}
		}
		if (match)
			return 1;
	}

	for (int i = 0; i < learned_count; i++) {
		struct learned_subnet *s = &learned[i];

		if (s->af != af || s->expires <= now)
			continue;
		has_subnet = 1;
		if (learned_match(s, af, ip))
			return 1;
	}

	if (!has_subnet)
		return 1;

	return 0;
}

int
capture_is_local(const char *iface, int af, const uint8_t *ip)
{
	int alen = ip_len(af);
	int has_subnet = 0;
	time_t now = time(NULL);

	/* link-local addresses are always valid on the local link */
	if (af == AF_INET6 && IS_LINKLOCAL6(ip))
		return 1;
	if (af == AF_INET && IS_LINKLOCAL4(ip))
		return 1;

	for (int i = 0; i < subnet_count; i++) {
		struct subnet *s = &subnets[i];

		if (s->af != af || strcmp(s->iface, iface) != 0)
			continue;
		has_subnet = 1;

		int match = 1;
		for (int j = 0; j < alen; j++) {
			if ((ip[j] & s->mask[j]) !=
			    (s->addr[j] & s->mask[j])) {
				match = 0;
				break;
			}
		}
		if (match)
			return 1;
	}

	for (int i = 0; i < learned_count; i++) {
		struct learned_subnet *s = &learned[i];

		if (s->af != af || s->expires <= now ||
		    strcmp(s->iface, iface) != 0)
			continue;
		has_subnet = 1;
		if (learned_match(s, af, ip))
			return 1;
	}

	/* no configured subnets for this af. cannot determine locality */
	if (!has_subnet)
		return 1;

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
		int dup = 0;
		for (int i = 0; i < count; i++) {
			if (strcmp(parents[i], parent) == 0) {
				dup = 1;
				break;
			}
		}
		if (!dup) {
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

		/* only consider actual VLAN interfaces */
		if (strncmp(dev->name, "vlan", 4) != 0)
			continue;

		memset(&ifp, 0, sizeof(ifp));
		snprintf(ifp.ifp_name, sizeof(ifp.ifp_name),
		    "%s", dev->name);
		if (ioctl(sock, SIOCGIFPARENT, &ifp) < 0)
			continue;
		if (ifp.ifp_parent[0] == '\0')
			continue;

		int dup = 0;
		for (int i = 0; i < count; i++) {
			if (strcmp(parents[i], ifp.ifp_parent) == 0) {
				dup = 1;
				break;
			}
		}
		if (!dup) {
			snprintf(parents[count], 32, "%s",
			    ifp.ifp_parent);
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

		int dup = 0;
		for (int i = 0; i < count; i++) {
			if (strcmp(parents[i], vreq.vlr_parent) == 0) {
				dup = 1;
				break;
			}
		}
		if (!dup) {
			snprintf(parents[count], 32, "%s",
			    vreq.vlr_parent);
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

	if (getifaddrs(&ifap) < 0)
		return count;

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

static int
is_vlan_parent(const char *name, char parents[][32], int count)
{
	for (int i = 0; i < count; i++) {
		if (strcmp(name, parents[i]) == 0)
			return 1;
	}
	return 0;
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
		int dlt;

		/* skip loopback */
		if (dev->flags & PCAP_IF_LOOPBACK)
			continue;

		/* skip VLAN trunk parents when monitoring all interfaces */
		if (nparents > 0 &&
		    is_vlan_parent(dev->name, vlan_parents, nparents)) {
			log_msg("skipping %s (has VLAN subinterfaces)",
			    dev->name);
			continue;
		}

		/* filter by interface name if specified */
		if (cfg.iface && strcmp(dev->name, cfg.iface) != 0)
			continue;

		p = pcap_create(dev->name, errbuf);
		if (!p) {
			log_err("pcap_create(%s): %s", dev->name, errbuf);
			continue;
		}

		pcap_set_snaplen(p, SNAP_LEN);
		pcap_set_promisc(p, 0);
		pcap_set_timeout(p, POLL_TIMEOUT_MS);

		/* immediate mode: deliver packets to poll() without
		 * waiting for BPF buffer timeout (needed on BSDs) */
		pcap_set_immediate_mode(p, 1);

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

		snprintf(ifaces[count].name, sizeof(ifaces[count].name),
		         "%s", dev->name);
		ifaces[count].handle = p;
		ifaces[count].fd = fd;
		memset(ifaces[count].local_mac, 0,
		    sizeof(ifaces[count].local_mac));

		log_msg("monitoring %s", dev->name);
		count++;
	}

	pcap_freealldevs(alldevs);
	fill_local_macs(ifaces, count);
	fill_local_subnets(ifaces, count);
	fill_local_ips(ifaces, count);
	return count;
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

