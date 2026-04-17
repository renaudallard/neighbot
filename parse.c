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

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <string.h>

#if defined(__OpenBSD__)
#include <net/if.h>
#include <netinet/if_ether.h>
#elif defined(__NetBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#include "neighbot.h"
#include "capture.h"
#include "db.h"
#include "log.h"
#include "notify.h"
#include "parse.h"
#include "probe.h"

/* ARP header */
struct arp_pkt {
	uint16_t htype;
	uint16_t ptype;
	uint8_t  hlen;
	uint8_t  plen;
	uint16_t oper;
	uint8_t  sha[6];
	uint8_t  spa[4];
	uint8_t  tha[6];
	uint8_t  tpa[4];
};

static int
is_zero_ip4(const uint8_t *ip)
{
	return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

static int
is_zero_ip6(const uint8_t *ip)
{
	for (int i = 0; i < 16; i++)
		if (ip[i] != 0)
			return 0;
	return 1;
}

static int
is_multicast_mac(const uint8_t *mac)
{
	return mac[0] & 0x01;
}


#define STORM_CACHE_SIZE 32

struct storm_slot {
	int     af;
	uint8_t ip[16];
	char    iface[32];
	uint8_t mac_a[6];
	uint8_t mac_b[6];
	time_t  first_flip;
	time_t  last_flip;
	int     count;
	int     suppressed;
};

static struct storm_slot storm_cache[STORM_CACHE_SIZE];

void
storm_reset(void)
{
	memset(storm_cache, 0, sizeof(storm_cache));
}

/*
 * Check if a flip-flop event is part of an address conflict storm.
 * Returns 1 if the event should be suppressed, 0 otherwise.
 */
static int
storm_check(int af, const uint8_t *ip, const uint8_t *mac,
            const uint8_t *old_mac, const char *iface)
{
	int ilen = ip_len(af);
	time_t now = time(NULL);
	int found = -1;
	int empty = -1;
	int oldest = 0;
	time_t oldest_time = 0;

	for (int i = 0; i < STORM_CACHE_SIZE; i++) {
		if (storm_cache[i].count == 0) {
			if (empty < 0)
				empty = i;
			continue;
		}
		if (storm_cache[i].af == af &&
		    memcmp(storm_cache[i].ip, ip, ilen) == 0) {
			found = i;
			break;
		}
		if (oldest_time == 0 ||
		    storm_cache[i].last_flip < oldest_time) {
			oldest_time = storm_cache[i].last_flip;
			oldest = i;
		}
	}

	if (found >= 0) {
		struct storm_slot *s = &storm_cache[found];

		if (s->suppressed) {
			if (now - s->last_flip >= STORM_RECOVER) {
				char ipstr[INET6_ADDRSTRLEN];

				inet_ntop(af, ip, ipstr, sizeof(ipstr));
				log_msg("address conflict storm for %s "
				    "appears resolved", ipstr);
				memset(s, 0, sizeof(*s));
				empty = found;
				found = -1;
			} else {
				s->last_flip = now;
				return 1;
			}
		}
	}

	if (found >= 0) {
		struct storm_slot *s = &storm_cache[found];

		if (now - s->first_flip > STORM_WINDOW) {
			s->first_flip = now;
			s->count = 1;
		} else {
			s->count++;
		}
		s->last_flip = now;
		memcpy(s->mac_a, mac, 6);
		memcpy(s->mac_b, old_mac, 6);
		snprintf(s->iface, sizeof(s->iface), "%s", iface);

		if (s->count >= STORM_THRESHOLD) {
			char ipstr[INET6_ADDRSTRLEN];
			char macstr_a[18], macstr_b[18];

			s->suppressed = 1;
			inet_ntop(af, ip, ipstr, sizeof(ipstr));
			format_mac(mac, macstr_a, sizeof(macstr_a));
			format_mac(old_mac, macstr_b, sizeof(macstr_b));
			log_msg("address conflict storm detected "
			    "for %s (%s <-> %s) on %s, suppressing",
			    ipstr, macstr_a, macstr_b, iface);
			if (!cfg.quiet)
				notify_storm(af, ip, mac, old_mac,
				    iface);
			return 1;
		}
		return 0;
	}

	/* not found, create new entry */
	int slot = (empty >= 0) ? empty : oldest;
	struct storm_slot *s = &storm_cache[slot];

	memset(s, 0, sizeof(*s));
	s->af = af;
	memcpy(s->ip, ip, ilen);
	memcpy(s->mac_a, mac, 6);
	memcpy(s->mac_b, old_mac, 6);
	snprintf(s->iface, sizeof(s->iface), "%s", iface);
	s->first_flip = now;
	s->last_flip = now;
	s->count = 1;
	return 0;
}

static void
handle_event(int event, int af, const uint8_t *ip, const uint8_t *mac,
             const uint8_t *old_mac, const char *iface,
             time_t old_last_seen)
{
	char ipstr[INET6_ADDRSTRLEN];
	char macstr[18], oldmacstr[18];

	inet_ntop(af, ip, ipstr, sizeof(ipstr));
	format_mac(mac, macstr, sizeof(macstr));

	if (event == EVENT_NEW) {
		/* detect temporary IPv6 address rotation: if this
		 * non-EUI-64 address shares a /64 with an existing
		 * non-EUI-64 entry for this MAC, suppress "new
		 * station" and let probing report "moved" instead */
		int temp_rotate = (af == AF_INET6 &&
		    !is_eui64(ip, mac) &&
		    db_has_temp_in_prefix(mac, ip));

		if (temp_rotate) {
			log_msg("new temporary %s %s on %s",
			    ipstr, macstr, iface);
		} else {
			log_msg("new station %s %s on %s",
			    ipstr, macstr, iface);
			if (!cfg.quiet)
				notify_new(af, ip, mac, iface);
		}

		/* schedule probes for other IPs of this MAC.
		 * skip if new IP is link-local since every IPv6
		 * interface has one alongside its global address */
		if (cfg.probe &&
		    !(af == AF_INET6 && IS_LINKLOCAL6(ip)) &&
		    !(af == AF_INET && IS_LINKLOCAL4(ip))) {
			struct db_entry_info others[PROBE_MAX_SLOTS];
			int n = db_find_other_entries(mac, af, ip,
			    others, PROBE_MAX_SLOTS);
			for (int i = 0; i < n; i++) {
				if (capture_is_own_ip(others[i].af,
				    others[i].ip))
					continue;
				/* temp rotation: skip probing other
				 * temp addresses in the same /64 */
				if (temp_rotate &&
				    others[i].af == AF_INET6 &&
				    memcmp(others[i].ip, ip, 8) == 0 &&
				    !is_eui64(others[i].ip, mac))
					continue;
				probe_schedule(others[i].af, others[i].ip,
				    mac, af, ip, others[i].iface);
			}
		}
	} else if (event == EVENT_CHANGED) {
		format_mac(old_mac, oldmacstr, sizeof(oldmacstr));
		log_msg("changed station %s %s -> %s on %s",
		        ipstr, oldmacstr, macstr, iface);
		if (!cfg.quiet)
			notify_changed(af, ip, mac, old_mac, iface,
			               old_last_seen);
	} else if (event == EVENT_FLIPFLOP) {
		if (!storm_check(af, ip, mac, old_mac, iface)) {
			format_mac(old_mac, oldmacstr, sizeof(oldmacstr));
			log_msg("flip-flop station %s %s <-> %s on %s",
			    ipstr, oldmacstr, macstr, iface);
			if (!cfg.quiet)
				notify_flipflop(af, ip, mac, old_mac,
				    iface, old_last_seen);
		}
	} else if (event == EVENT_REAPPEARED) {
		log_msg("reappeared station %s %s on %s", ipstr, macstr,
		        iface);
		if (!cfg.quiet)
			notify_reappeared(af, ip, mac, iface,
			                  old_last_seen);
	}

	/* trigger save in main loop */
	save = 1;
}

void
handle_moved(int new_af, const uint8_t *new_ip, const uint8_t *mac,
             int old_af, const uint8_t *old_ip, const char *iface)
{
	char newstr[INET6_ADDRSTRLEN];
	char oldstr[INET6_ADDRSTRLEN];
	char macstr[18];

	inet_ntop(new_af, new_ip, newstr, sizeof(newstr));
	inet_ntop(old_af, old_ip, oldstr, sizeof(oldstr));
	format_mac(mac, macstr, sizeof(macstr));

	log_msg("moved station %s %s -> %s on %s",
	        macstr, oldstr, newstr, iface);
	if (!cfg.quiet)
		notify_moved(new_af, new_ip, mac, old_af, old_ip, iface);

	save = 1;
}

void
handle_multiple_ips(int af, const uint8_t *ip, const uint8_t *mac,
                    int other_af, const uint8_t *other_ip,
                    const char *iface)
{
	char ipstr[INET6_ADDRSTRLEN];
	char otherstr[INET6_ADDRSTRLEN];

	(void)mac;
	(void)iface;

	inet_ntop(af, ip, ipstr, sizeof(ipstr));
	inet_ntop(other_af, other_ip, otherstr, sizeof(otherstr));
	log_msg("probe: %s still active, device has multiple IPs (also %s)",
	    ipstr, otherstr);
}

#define BOGON_CACHE_SIZE 128

struct bogon_slot {
	int     af;
	uint8_t ip[16];
	char    iface[32];
	time_t  last_notified;
};

static struct bogon_slot bogon_cache[BOGON_CACHE_SIZE];

static int
bogon_should_notify(int af, const uint8_t *ip, const char *iface, time_t now)
{
	int ilen = ip_len(af);
	int oldest = 0;
	time_t oldest_time = bogon_cache[0].last_notified;
	int empty = -1;

	for (int i = 0; i < BOGON_CACHE_SIZE; i++) {
		if (bogon_cache[i].last_notified == 0) {
			if (empty < 0)
				empty = i;
			continue;
		}
		if (bogon_cache[i].af == af &&
		    memcmp(bogon_cache[i].ip, ip, ilen) == 0 &&
		    strcmp(bogon_cache[i].iface, iface) == 0) {
			if (now - bogon_cache[i].last_notified <
			    cfg.bogon_cooldown)
				return 0;
			bogon_cache[i].last_notified = now;
			return 1;
		}
		if (bogon_cache[i].last_notified < oldest_time) {
			oldest_time = bogon_cache[i].last_notified;
			oldest = i;
		}
	}

	/* insert into empty slot or evict oldest */
	int slot = (empty >= 0) ? empty : oldest;
	bogon_cache[slot].af = af;
	memset(bogon_cache[slot].ip, 0, sizeof(bogon_cache[slot].ip));
	memcpy(bogon_cache[slot].ip, ip, ilen);
	snprintf(bogon_cache[slot].iface, sizeof(bogon_cache[slot].iface),
	    "%s", iface);
	bogon_cache[slot].last_notified = now;
	return 1;
}

static void
handle_bogon(int af, const uint8_t *ip, const uint8_t *mac,
             const char *iface)
{
	char ipstr[INET6_ADDRSTRLEN];
	char macstr[18];

	inet_ntop(af, ip, ipstr, sizeof(ipstr));
	format_mac(mac, macstr, sizeof(macstr));
	log_msg("bogon %s %s on %s", ipstr, macstr, iface);
	if (!cfg.quiet) {
		if (cfg.bogon_cooldown == 0 ||
		    bogon_should_notify(af, ip, iface, time(NULL)))
			notify_bogon(af, ip, mac, iface);
	}
}

static void
parse_arp(const u_char *pkt, size_t len, const char *iface)
{
	const struct arp_pkt *arp;
	uint8_t old_mac[6];
	time_t old_last_seen = 0;
	int event;

	if (len < sizeof(struct arp_pkt))
		return;

	arp = (const struct arp_pkt *)pkt;

	/* validate: Ethernet + IPv4, correct lengths */
	if (ntohs(arp->htype) != ARPHRD_ETHER)
		return;
	if (ntohs(arp->ptype) != ETHERTYPE_IP)
		return;
	if (arp->hlen != 6 || arp->plen != 4)
		return;

	/* skip ARP probes (sender IP 0.0.0.0) */
	if (is_zero_ip4(arp->spa))
		return;

	/* skip broadcast and multicast sender MACs and IPs */
	if (is_multicast_mac(arp->sha))
		return;
	if (arp->spa[0] >= 224)
		return;

	if (!capture_is_local(iface, AF_INET, arp->spa)) {
		if (!capture_is_local_any(AF_INET, arp->spa))
			handle_bogon(AF_INET, arp->spa, arp->sha, iface);
		return;
	}

	event = db_update(AF_INET, arp->spa, arp->sha, iface, old_mac,
	                  &old_last_seen);
	if (cfg.probe)
		probe_mark_seen(AF_INET, arp->spa, arp->sha);
	if (event)
		handle_event(event, AF_INET, arp->spa, arp->sha,
		             old_mac, iface, old_last_seen);
}

/* NDP option header */
struct ndp_opt {
	uint8_t  type;
	uint8_t  len;   /* in units of 8 octets */
};

static const uint8_t *
ndp_find_lladdr_opt(const u_char *opts, size_t opts_len, uint8_t want_type)
{
	size_t off = 0;

	while (off + 2 <= opts_len) {
		const struct ndp_opt *opt = (const struct ndp_opt *)(opts + off);
		size_t olen = (size_t)opt->len * 8;

		if (olen == 0 || off + olen > opts_len)
			break;

		/* type 1 = Source LLA, type 2 = Target LLA */
		if (opt->type == want_type && olen >= 8)
			return opts + off + 2;

		off += olen;
	}
	return NULL;
}

static uint32_t
read_u32_be(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

static void
parse_ra(const uint8_t *icmp, size_t icmp_len, const char *iface,
         const uint8_t *router_src)
{
	/* RA fixed part is 16 bytes */
	if (icmp_len < 16)
		return;

	const u_char *opts = icmp + 16;
	size_t opts_len = icmp_len - 16;
	size_t off = 0;

	while (off + 2 <= opts_len) {
		uint8_t otype = opts[off];
		uint8_t olen8 = opts[off + 1];
		size_t olen = (size_t)olen8 * 8;

		if (olen == 0 || off + olen > opts_len)
			break;

		/* Prefix Information Option (type 3, length 4 -> 32 bytes) */
		if (otype == 3 && olen >= 32) {
			uint8_t prefix_len = opts[off + 2];
			uint8_t flags      = opts[off + 3];
			uint32_t valid     = read_u32_be(opts + off + 4);
			const uint8_t *prefix = opts + off + 16;

			/* require on-link (L) flag and non-zero lifetime */
			if (!(flags & 0x80))
				goto next;
			if (valid == 0)
				goto next;
			if (prefix_len == 0 || prefix_len > 128)
				goto next;

			/* skip link-local, multicast, unspecified */
			if (IS_LINKLOCAL6(prefix))
				goto next;
			if (prefix[0] == 0xff)
				goto next;
			if (is_zero_ip6(prefix))
				goto next;

			int added = capture_add_learned_subnet(iface,
			    AF_INET6, prefix, prefix_len, valid);

			if (added == 1) {
				char pfxstr[INET6_ADDRSTRLEN];
				char rtrstr[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, prefix, pfxstr,
				    sizeof(pfxstr));
				inet_ntop(AF_INET6, router_src, rtrstr,
				    sizeof(rtrstr));
				log_msg("learned prefix %s/%u on %s "
				    "(router %s, lifetime %us)",
				    pfxstr, prefix_len, iface, rtrstr,
				    (unsigned)valid);
				if (!cfg.quiet)
					notify_ra_learned(iface, prefix,
					    prefix_len, router_src, valid);
			}
		}

next:
		off += olen;
	}
}

static void
parse_ndp(const u_char *pkt, size_t len, const char *iface,
          const uint8_t *eth_src)
{
	const struct ip6_hdr *ip6;
	const uint8_t *icmp;
	uint8_t type;
	size_t icmp_off, icmp_len;
	const uint8_t *ip_addr;
	const uint8_t *mac;
	const u_char *opts;
	size_t opts_len;
	uint8_t old_mac[6];
	time_t old_last_seen = 0;
	int event;

	if (len < sizeof(struct ip6_hdr))
		return;

	ip6 = (const struct ip6_hdr *)pkt;

	/* require ICMPv6 directly — skip packets with extension headers */
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		return;

	icmp_off = sizeof(struct ip6_hdr);
	if (len < icmp_off + 4)
		return;

	icmp = pkt + icmp_off;
	icmp_len = len - icmp_off;
	type = icmp[0];

	if (type == ND_ROUTER_ADVERT) {
		parse_ra(icmp, icmp_len, iface,
		    (const uint8_t *)&ip6->ip6_src);
		return;
	}

	if (type == ND_NEIGHBOR_ADVERT) {
		/* NA: type(1) + code(1) + cksum(2) + flags(4) + target(16) + opts */
		if (icmp_len < 24)
			return;
		ip_addr = icmp + 8;  /* target address */
		opts = icmp + 24;
		opts_len = icmp_len - 24;
		/* look for Target Link-Layer Address (type 2) */
		mac = ndp_find_lladdr_opt(opts, opts_len, 2);
	} else if (type == ND_NEIGHBOR_SOLICIT) {
		/* NS: type(1) + code(1) + cksum(2) + reserved(4) + target(16) + opts */
		if (icmp_len < 24)
			return;
		/* use source IP from IPv6 header */
		ip_addr = (const uint8_t *)&ip6->ip6_src;
		opts = icmp + 24;
		opts_len = icmp_len - 24;
		/* look for Source Link-Layer Address (type 1) */
		mac = ndp_find_lladdr_opt(opts, opts_len, 1);
	} else {
		return;
	}

	/* fall back to Ethernet source MAC if NDP option is missing */
	if (!mac)
		mac = eth_src;

	/* skip DAD probes (source ::) */
	if (is_zero_ip6((const uint8_t *)&ip6->ip6_src))
		return;

	/* skip multicast/broadcast MACs */
	if (is_multicast_mac(mac))
		return;

	/* skip multicast IPs (ff00::/8) */
	if (ip_addr[0] == 0xff)
		return;

	if (!capture_is_local(iface, AF_INET6, ip_addr)) {
		if (!capture_is_local_any(AF_INET6, ip_addr))
			handle_bogon(AF_INET6, ip_addr, mac, iface);
		return;
	}

	/* for NA, use the target address; for NS, use source IP */
	event = db_update(AF_INET6, ip_addr, mac, iface, old_mac,
	                  &old_last_seen);
	if (cfg.probe)
		probe_mark_seen(AF_INET6, ip_addr, mac);
	if (event)
		handle_event(event, AF_INET6, ip_addr, mac, old_mac, iface,
		             old_last_seen);
}

void
parse_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	const char *iface = (const char *)user;
	const struct ether_header *eh;
	uint16_t etype;
	size_t len = hdr->caplen;

	if (len < sizeof(struct ether_header))
		return;

	eh = (const struct ether_header *)pkt;
	etype = ntohs(eh->ether_type);

	if (etype == ETHERTYPE_ARP) {
		parse_arp(pkt + sizeof(struct ether_header),
		          len - sizeof(struct ether_header), iface);
	} else if (etype == ETHERTYPE_IPV6) {
		parse_ndp(pkt + sizeof(struct ether_header),
		          len - sizeof(struct ether_header), iface,
		          eh->ether_shost);
	}
}
