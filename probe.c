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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <time.h>

#include "neighbot.h"
#include "capture.h"
#include "log.h"
#include "notify.h"
#include "probe.h"

struct probe {
	int      active;
	int      af;
	uint8_t  ip[16];       /* old IP to probe */
	uint8_t  mac[6];       /* expected MAC */
	uint8_t  new_ip[16];   /* new IP (for notification) */
	int      new_af;
	char     iface[32];
	int      tries;
	time_t   first_sent;
	time_t   last_sent;
	int      answered;
};

static struct probe probes[PROBE_MAX_SLOTS];

/* Build ARP request: 42 bytes total.
 * spa=0.0.0.0 (RFC 5227 probe), tpa=target IP.
 * src_mac is the interface's local MAC. */
static int
build_arp_request(uint8_t *buf, size_t buflen,
                  const uint8_t *src_mac, const uint8_t *target_ip)
{
	if (buflen < 42)
		return -1;

	memset(buf, 0, 42);

	/* Ethernet header: dst=broadcast, src=local MAC, type=ARP */
	memset(buf, 0xff, 6);
	memcpy(buf + 6, src_mac, 6);
	buf[12] = 0x08;
	buf[13] = 0x06;

	/* ARP: htype=1(Ethernet), ptype=0x0800(IPv4), hlen=6, plen=4 */
	buf[14] = 0x00; buf[15] = 0x01;   /* htype */
	buf[16] = 0x08; buf[17] = 0x00;   /* ptype */
	buf[18] = 6;                       /* hlen */
	buf[19] = 4;                       /* plen */
	buf[20] = 0x00; buf[21] = 0x01;   /* oper=request */

	/* sender hardware address */
	memcpy(buf + 22, src_mac, 6);
	/* sender protocol address: 0.0.0.0 */
	/* (already zeroed) */

	/* target hardware address: 00:00:00:00:00:00 */
	/* (already zeroed) */

	/* target protocol address */
	memcpy(buf + 38, target_ip, 4);

	return 42;
}

/* ICMPv6 checksum over pseudo-header + payload */
static uint16_t
icmp6_checksum(const uint8_t *src6, const uint8_t *dst6,
               const uint8_t *icmp, size_t icmplen)
{
	uint32_t sum = 0;

	/* pseudo-header: src, dst, length (32-bit), next header */
	for (int i = 0; i < 16; i += 2)
		sum += ((uint32_t)src6[i] << 8) | src6[i + 1];
	for (int i = 0; i < 16; i += 2)
		sum += ((uint32_t)dst6[i] << 8) | dst6[i + 1];
	sum += (uint32_t)icmplen;
	sum += IPPROTO_ICMPV6;

	/* ICMPv6 payload */
	for (size_t i = 0; i + 1 < icmplen; i += 2)
		sum += ((uint32_t)icmp[i] << 8) | icmp[i + 1];
	if (icmplen & 1)
		sum += (uint32_t)icmp[icmplen - 1] << 8;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

/* Build NDP Neighbor Solicitation: ~78 bytes.
 * src=::, dst=solicited-node multicast of target.
 * No Source LLA option (src is ::). */
static int
build_ndp_ns(uint8_t *buf, size_t buflen,
             const uint8_t *src_mac, const uint8_t *target_ip6)
{
	uint8_t sol_node_mc[16];   /* ff02::1:ffXX:YYZZ */
	uint8_t sol_node_mac[6];   /* 33:33:ff:XX:YY:ZZ */
	uint8_t src_ip6[16];       /* :: */
	uint16_t cksum;
	size_t off;

	if (buflen < 78)
		return -1;

	memset(buf, 0, 78);

	/* solicited-node multicast address */
	memset(sol_node_mc, 0, sizeof(sol_node_mc));
	sol_node_mc[0] = 0xff;
	sol_node_mc[1] = 0x02;
	sol_node_mc[11] = 0x01;
	sol_node_mc[12] = 0xff;
	sol_node_mc[13] = target_ip6[13];
	sol_node_mc[14] = target_ip6[14];
	sol_node_mc[15] = target_ip6[15];

	/* solicited-node multicast MAC: 33:33:ff:XX:YY:ZZ */
	sol_node_mac[0] = 0x33;
	sol_node_mac[1] = 0x33;
	sol_node_mac[2] = 0xff;
	sol_node_mac[3] = target_ip6[13];
	sol_node_mac[4] = target_ip6[14];
	sol_node_mac[5] = target_ip6[15];

	memset(src_ip6, 0, sizeof(src_ip6));

	/* Ethernet header */
	memcpy(buf, sol_node_mac, 6);
	memcpy(buf + 6, src_mac, 6);
	buf[12] = 0x86;
	buf[13] = 0xdd;
	off = 14;

	/* IPv6 header (40 bytes) */
	buf[off] = 0x60;            /* version=6, traffic class=0 */
	/* payload length = ICMPv6 (24 bytes NS, no options) */
	buf[off + 4] = 0x00;
	buf[off + 5] = 24;
	buf[off + 6] = IPPROTO_ICMPV6;
	buf[off + 7] = 255;         /* hop limit */
	/* src = :: (already zeroed) */
	memcpy(buf + off + 24, sol_node_mc, 16);   /* dst */
	off += 40;

	/* ICMPv6 Neighbor Solicitation (24 bytes, no options) */
	buf[off] = 135;             /* type: NS */
	buf[off + 1] = 0;          /* code */
	/* checksum at off+2..off+3, fill after */
	/* reserved (4 bytes, zeroed) */
	memcpy(buf + off + 8, target_ip6, 16);   /* target address */

	cksum = icmp6_checksum(src_ip6, sol_node_mc,
	    buf + off, 24);
	buf[off + 2] = (uint8_t)(cksum >> 8);
	buf[off + 3] = (uint8_t)(cksum & 0xff);

	return 78;
}

void
probe_schedule(int af, const uint8_t *ip, const uint8_t *mac,
               int new_af, const uint8_t *new_ip, const char *iface)
{
	/* check for duplicate probe */
	for (int i = 0; i < PROBE_MAX_SLOTS; i++) {
		if (!probes[i].active)
			continue;
		if (probes[i].af == af &&
		    memcmp(probes[i].ip, ip, 16) == 0 &&
		    memcmp(probes[i].mac, mac, 6) == 0)
			return;
	}

	for (int i = 0; i < PROBE_MAX_SLOTS; i++) {
		if (probes[i].active)
			continue;

		probes[i].active = 1;
		probes[i].af = af;
		memcpy(probes[i].ip, ip, 16);
		memcpy(probes[i].mac, mac, 6);
		probes[i].new_af = new_af;
		memset(probes[i].new_ip, 0, sizeof(probes[i].new_ip));
		memcpy(probes[i].new_ip, new_ip,
		    (new_af == AF_INET) ? 4 : 16);
		snprintf(probes[i].iface, sizeof(probes[i].iface),
		    "%s", iface);
		probes[i].tries = 0;
		probes[i].first_sent = 0;
		probes[i].last_sent = 0;
		probes[i].answered = 0;

		{
			char ipstr[INET6_ADDRSTRLEN];
			inet_ntop(af, ip, ipstr, sizeof(ipstr));
			log_msg("probe: scheduled for %s on %s",
			    ipstr, iface);
		}
		return;
	}

	log_msg("probe: no free slots");
}

void
probe_mark_seen(int af, const uint8_t *ip, const uint8_t *mac)
{
	int ilen = (af == AF_INET) ? 4 : 16;

	for (int i = 0; i < PROBE_MAX_SLOTS; i++) {
		if (!probes[i].active)
			continue;
		if (probes[i].af != af)
			continue;
		if (memcmp(probes[i].ip, ip, ilen) != 0)
			continue;
		if (memcmp(probes[i].mac, mac, 6) != 0)
			continue;
		probes[i].answered = 1;
	}
}

/* Find the iface struct matching a name */
static struct iface *
find_iface(struct iface *ifaces, int nifaces, const char *name)
{
	for (int i = 0; i < nifaces; i++) {
		if (ifaces[i].handle &&
		    strcmp(ifaces[i].name, name) == 0)
			return &ifaces[i];
	}
	return NULL;
}

static void
send_probe(struct probe *p, struct iface *ifp)
{
	uint8_t pkt[128];
	int len;

	if (p->af == AF_INET) {
		len = build_arp_request(pkt, sizeof(pkt),
		    ifp->local_mac, p->ip);
	} else {
		len = build_ndp_ns(pkt, sizeof(pkt),
		    ifp->local_mac, p->ip);
	}

	if (len < 0)
		return;

	if (pcap_inject(ifp->handle, pkt, len) < 0) {
		log_err("probe: pcap_inject(%s): %s",
		    ifp->name, pcap_geterr(ifp->handle));
	}
}

void
probe_tick(struct iface *ifaces, int nifaces)
{
	time_t now = time(NULL);

	for (int i = 0; i < PROBE_MAX_SLOTS; i++) {
		struct probe *p = &probes[i];
		struct iface *ifp;

		if (!p->active)
			continue;

		/* answered: device has multiple IPs */
		if (p->answered) {
			char ipstr[INET6_ADDRSTRLEN];
			char newstr[INET6_ADDRSTRLEN];

			inet_ntop(p->af, p->ip, ipstr, sizeof(ipstr));
			inet_ntop(p->new_af, p->new_ip, newstr,
			    sizeof(newstr));
			log_msg("probe: %s still active, "
			    "device has multiple IPs (also %s)",
			    ipstr, newstr);
			p->active = 0;
			continue;
		}

		/* timed out after all attempts */
		if (p->tries >= PROBE_MAX_TRIES &&
		    now - p->last_sent >= PROBE_TIMEOUT) {
			char ipstr[INET6_ADDRSTRLEN];
			char newstr[INET6_ADDRSTRLEN];

			inet_ntop(p->af, p->ip, ipstr, sizeof(ipstr));
			inet_ntop(p->new_af, p->new_ip, newstr,
			    sizeof(newstr));
			log_msg("probe: %s not responding, "
			    "device moved to %s", ipstr, newstr);
			if (!cfg.quiet)
				notify_moved(p->new_af, p->new_ip,
				    p->mac, p->af, p->ip, p->iface);
			p->active = 0;
			continue;
		}

		/* time to send (next) probe */
		if (p->tries == 0 ||
		    now - p->last_sent >= PROBE_TIMEOUT) {
			ifp = find_iface(ifaces, nifaces, p->iface);
			if (!ifp) {
				p->active = 0;
				continue;
			}

			send_probe(p, ifp);
			p->tries++;
			if (p->first_sent == 0)
				p->first_sent = now;
			p->last_sent = now;
		}
	}
}
