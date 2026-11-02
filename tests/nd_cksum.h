/*
 * Shared by the parser test and fuzz harnesses, which build or receive
 * frames without a valid ICMPv6 checksum. nd_fix_cksum() sets it in an
 * Ethernet frame holding an IPv6 packet, behind any priority tags and
 * extension headers, the way parse_packet() finds the ICMPv6 header.
 * Frames it cannot follow are left alone.
 */

#ifndef ND_CKSUM_H
#define ND_CKSUM_H

#include <stddef.h>
#include <stdint.h>

#include "../neighbot.h"

static void
nd_fix_cksum(uint8_t *pkt, size_t len)
{
	size_t off = 12, ip, end;
	uint16_t etype, c;
	uint8_t nxt;

	for (;;) {
		if (len < off + 2)
			return;
		etype = (uint16_t)(pkt[off] << 8 | pkt[off + 1]);
		if (etype != 0x8100 && etype != 0x88a8)
			break;
		off += 4;
	}
	ip = off + 2;
	if (etype != 0x86dd || len < ip + 40)
		return;
	end = ip + 40 + (size_t)(pkt[ip + 4] << 8 | pkt[ip + 5]);
	if (end > len)
		return;
	nxt = pkt[ip + 6];
	off = ip + 40;
	while (nxt == 0 || nxt == 43 || nxt == 60) {
		if (end < off + 2)
			return;
		nxt = pkt[off];
		off += ((size_t)pkt[off + 1] + 1) * 8;
	}
	if (nxt != 58 || end < off + 4)
		return;
	pkt[off + 2] = pkt[off + 3] = 0;
	c = icmp6_checksum(pkt + ip + 8, pkt + ip + 24, pkt + off, end - off);
	pkt[off + 2] = (uint8_t)(c >> 8);
	pkt[off + 3] = (uint8_t)c;
}

#endif
