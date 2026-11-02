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

#ifndef NEIGHBOT_H
#define NEIGHBOT_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#define NEIGHBOT_VERSION "0.5.17"

#define DEFAULT_DBDIR   "/var/neighbot"
#define DEFAULT_DBFILE  DEFAULT_DBDIR "/neighbot.csv"
#define DEFAULT_MAILTO  "root"
#define DEFAULT_USER    "nobody"
#define DEFAULT_OUIFILE  DEFAULT_DBDIR "/oui.txt"
#define DEFAULT_SENDMAIL "/usr/sbin/sendmail"
#define OPENBSD_OUIFILE  "/usr/local/share/arp-scan/ieee-oui.txt"

#define HT_BUCKETS      1024
#define MAX_ENTRIES      100000
#define MAX_IFACES       64
#define SNAP_LEN         9216               /* whole jumbo frames fit */
#define POLL_TIMEOUT_MS  1000
#define MAX_SUBNETS      256
#define MAX_LEARNED_SUBNETS 64
#define MAX_LOCAL_IPS    256
#define REAPPEAR_SECS    (180 * 24 * 3600)  /* 6 months */
#define DEFAULT_BOGON_COOLDOWN 1800         /* 30 minutes */
#define EXPIRE_CHECK_INTERVAL 3600          /* 1 hour */
#define SAVE_MIN_INTERVAL 10                 /* min seconds between db saves */
#define ADDR_REFRESH_INTERVAL 60             /* re-read interface addresses */
#define TEMP_IDLE_EXPIRE (7 * 24 * 3600)    /* RFC 4941 default valid_lft */
#define MAX_PER_MAC      256                 /* cap total entries per MAC */
#define LEARNED_MAX_LIFETIME   (7 * 24 * 3600) /* cap RA lifetime at 7 days */
#define LEARNED_MIN_PREFIX6    48                /* reject shorter on-link prefixes */
#define STORM_THRESHOLD  5                   /* flips within window */
#define STORM_WINDOW     60                  /* seconds */
#define STORM_RECOVER    1800                /* seconds of quiet */
#define NOTIFY_MAX_INFLIGHT 32               /* cap concurrent notify children */

/* ARP, ND (RS, RA, NS, NA, Redirect) right after the IPv6 header, and
 * IPv6 packets starting with a hop-by-hop, routing or destination
 * options header, which the parser walks to find ND behind them; the
 * same inside an 802.1Q or 802.1ad priority tag (VLAN ID 0), and any
 * frame with two such tags or more, which the parser unwraps. A vlan
 * clause shifts the offsets of every primitive after it, so each must
 * come last. */
#define BPF_NDP    "(icmp6 and ip6[40] >= 133 and ip6[40] <= 137)"
#define BPF_EXTHDR "(ip6 and (ip6[6] == 0 or ip6[6] == 43 or ip6[6] == 60))"
#define BPF_MATCH  "arp or " BPF_NDP " or " BPF_EXTHDR
#if defined(__OpenBSD__)
/* The vlan keyword of OpenBSD's libpcap keeps the offsets it shifts in
 * static state that is never reset, so only the first filter compiled
 * looks inside the tag; every vlan keyword tests the outer tag, and
 * 802.1ad is unknown. Test the tags at absolute offsets instead: the
 * match moved past one priority tag, or a second priority tag. */
#define BPF_FILTER BPF_MATCH " or " \
	"((ether[12:2] == 0x8100 or ether[12:2] == 0x88a8) and " \
	"ether[14:2] & 0x0fff == 0 and (ether[16:2] == 0x0806 or " \
	"(ether[16:2] == 0x86dd and ((ether[24] == 58 and " \
	"ether[58] >= 133 and ether[58] <= 137) or ether[24] == 0 or " \
	"ether[24] == 43 or ether[24] == 60)) or " \
	"((ether[16:2] == 0x8100 or ether[16:2] == 0x88a8) and " \
	"ether[18:2] & 0x0fff == 0)))"
#else
#define BPF_FILTER BPF_MATCH " or (vlan 0 and (" BPF_MATCH " or vlan 0))"
#endif

#define IS_LINKLOCAL6(ip) ((ip)[0] == 0xfe && ((ip)[1] & 0xc0) == 0x80)
#define IS_LINKLOCAL4(ip) ((ip)[0] == 169 && (ip)[1] == 254)

struct config {
	int    daemonize;
	int    quiet;
	int    probe;
	int    report;
	int    oui_explicit;
	int    bogon_cooldown;
	int    expire_secs;
	char  *dbfile;
	char  *iface;
	char  *mailto;
	char  *ouifile;
	char  *sendmail;
	char  *user;
};

extern struct config cfg;
extern volatile sig_atomic_t quit;
extern volatile sig_atomic_t save;

/* Seconds on the monotonic clock, for timers kept in memory (probes,
 * storm and bogon caches, learned prefixes) so that a wall-clock step
 * cannot stretch or cut them. Never 0, which marks unused cache slots. */
static inline time_t
mono_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return time(NULL);
	return ts.tv_sec + 1;
}

/* ICMPv6 checksum over the pseudo-header and the message. Over a message
 * that carries its checksum, it is 0 when that checksum is right. */
static inline uint16_t
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

	/* ICMPv6 message */
	for (size_t i = 0; i + 1 < icmplen; i += 2)
		sum += ((uint32_t)icmp[i] << 8) | icmp[i + 1];
	if (icmplen & 1)
		sum += (uint32_t)icmp[icmplen - 1] << 8;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

#endif
