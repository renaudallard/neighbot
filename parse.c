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

		/* schedule probes for other IPs of this MAC */
		if (cfg.probe) {
			struct db_entry_info others[PROBE_MAX_SLOTS];
			int n = db_find_other_entries(mac, af, ip,
			    others, PROBE_MAX_SLOTS);
			for (int i = 0; i < n; i++)
				probe_schedule(others[i].af, others[i].ip,
				    mac, af, ip, others[i].iface);
		}
	} else if (event == EVENT_CHANGED) {
		format_mac(old_mac, oldmacstr, sizeof(oldmacstr));
		log_msg("changed station %s %s -> %s on %s",
		        ipstr, oldmacstr, macstr, iface);
		if (!cfg.quiet)
			notify_changed(af, ip, mac, old_mac, iface,
			               old_last_seen);
	} else if (event == EVENT_FLIPFLOP) {
		format_mac(old_mac, oldmacstr, sizeof(oldmacstr));
		log_msg("flip-flop station %s %s <-> %s on %s",
		        ipstr, oldmacstr, macstr, iface);
		if (!cfg.quiet)
			notify_flipflop(af, ip, mac, old_mac, iface,
			                old_last_seen);
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

static void
handle_bogon(int af, const uint8_t *ip, const uint8_t *mac,
             const char *iface)
{
	char ipstr[INET6_ADDRSTRLEN];
	char macstr[18];

	inet_ntop(af, ip, ipstr, sizeof(ipstr));
	format_mac(mac, macstr, sizeof(macstr));
	log_msg("bogon %s %s on %s", ipstr, macstr, iface);
	if (!cfg.quiet)
		notify_bogon(af, ip, mac, iface);
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

	if (!capture_is_local(iface, AF_INET, arp->spa)) {
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

	if (!capture_is_local(iface, AF_INET6, ip_addr)) {
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
		          len - sizeof(struct ether_header), iface);
	}
}
