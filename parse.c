/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
#include "db.h"
#include "log.h"
#include "notify.h"
#include "parse.h"

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

static void
format_mac(const uint8_t *mac, char *buf, size_t len)
{
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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
		log_msg("new station %s %s on %s", ipstr, macstr, iface);
		if (!cfg.quiet)
			notify_new(af, ip, mac, iface);
	} else if (event == EVENT_CHANGED) {
		format_mac(old_mac, oldmacstr, sizeof(oldmacstr));
		log_msg("changed station %s %s -> %s on %s",
		        ipstr, oldmacstr, macstr, iface);
		if (!cfg.quiet)
			notify_changed(af, ip, mac, old_mac, iface,
			               old_last_seen);
	}
}

static void
parse_arp(const u_char *pkt, size_t len, const char *iface)
{
	const struct arp_pkt *arp;
	uint8_t old_mac[6];
	time_t old_last_seen;
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

	event = db_update(AF_INET, arp->spa, arp->sha, iface, old_mac,
	                  &old_last_seen);
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

static void
parse_ndp(const u_char *pkt, size_t len, const char *iface)
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
	time_t old_last_seen;
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

	if (!mac)
		return;

	/* skip DAD probes (source ::) */
	if (is_zero_ip6((const uint8_t *)&ip6->ip6_src))
		return;

	/* skip multicast/broadcast MACs */
	if (is_multicast_mac(mac))
		return;

	/* for NA, use the target address; for NS, use source IP */
	event = db_update(AF_INET6, ip_addr, mac, iface, old_mac,
	                  &old_last_seen);
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
		          len - sizeof(struct ether_header), iface);
	}
}
