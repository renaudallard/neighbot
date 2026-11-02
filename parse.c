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

#include <sys/param.h>
#include <sys/socket.h>

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

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_8021AD
#define ETHERTYPE_8021AD 0x88a8	/* 802.1ad service tag */
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
is_loopback_ip6(const uint8_t *ip)
{
	for (int i = 0; i < 15; i++)
		if (ip[i] != 0)
			return 0;
	return ip[15] == 1;
}


#define STORM_CACHE_SIZE 32

/* keyed by (iface, af, ip) like the database: the same address on two
 * links is two stations, and a storm on one must not silence the other */
struct storm_slot {
	int     af;
	uint8_t ip[16];
	char    iface[32];
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
 * Check if a changed or flip-flop event is part of an address conflict
 * storm. Returns 1 if the event should be suppressed, 0 otherwise.
 */
static int
storm_check(int af, const uint8_t *ip, const uint8_t *mac,
            const uint8_t *old_mac, const char *iface)
{
	int ilen = ip_len(af);
	time_t now = mono_now();
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
		    memcmp(storm_cache[i].ip, ip, ilen) == 0 &&
		    strcmp(storm_cache[i].iface, iface) == 0) {
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

		if (s->count >= STORM_THRESHOLD) {
			char ipstr[INET6_ADDRSTRLEN];
			char macstr_a[18], macstr_b[18];

			/* only suppress once the storm alert is out: if it
			 * was dropped (too many notifications in flight),
			 * suppressing now would silence this IP unnoticed,
			 * so report the event and retry on the next one */
			if (!cfg.quiet &&
			    !notify_storm(af, ip, mac, old_mac, iface))
				return 0;
			s->suppressed = 1;
			inet_ntop(af, ip, ipstr, sizeof(ipstr));
			format_mac(mac, macstr_a, sizeof(macstr_a));
			format_mac(old_mac, macstr_b, sizeof(macstr_b));
			log_msg("address conflict storm detected "
			    "for %s (%s <-> %s) on %s, suppressing",
			    ipstr, macstr_a, macstr_b, iface);
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
		 * station". Older temporaries are not dropped here: a
		 * spoofed new address from the owner's MAC would
		 * otherwise remove the owner's entry, letting another
		 * MAC take it over as a new address without a changed
		 * alert. The stale-temporary sweep reaps them. */
		int temp_rotate = (af == AF_INET6 &&
		    !is_eui64(ip, mac) &&
		    db_has_temp_in_prefix(mac, ip, iface));

		if (temp_rotate) {
			log_msg("new temporary %s %s on %s", ipstr, macstr,
			    iface);
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
				/* on a temporary address rotation the older
				 * temporaries on this link, in this /64 or in
				 * another one such as a ULA prefix next to a
				 * global one, expire on their own: probing
				 * one would only report it as moved. The
				 * stale non-EUI-64 sweep reaps them instead,
				 * and a non-EUI-64 address that is not
				 * temporary would only answer. */
				if (temp_rotate && others[i].af == AF_INET6 &&
				    strcmp(others[i].iface, iface) == 0 &&
				    !is_eui64(others[i].ip, mac))
					continue;
				probe_schedule(others[i].af, others[i].ip,
				    mac, af, ip, iface, others[i].iface);
			}
		}
	} else if (event == EVENT_CHANGED) {
		/* three or more MACs taking turns on one IP never repeat
		 * the previous MAC, so they show up as changed rather than
		 * flip-flop events and need the same storm check */
		if (!storm_check(af, ip, mac, old_mac, iface)) {
			format_mac(old_mac, oldmacstr, sizeof(oldmacstr));
			log_msg("changed station %s %s -> %s on %s",
			        ipstr, oldmacstr, macstr, iface);
			if (!cfg.quiet)
				notify_changed(af, ip, mac, old_mac, iface,
				               old_last_seen);
		}
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

/* The station with mac, last at old_ip on old_iface, is now at new_ip on
 * new_iface, and old_ip is gone from it. */
void
handle_moved(int new_af, const uint8_t *new_ip, const char *new_iface,
             const uint8_t *mac, int old_af, const uint8_t *old_ip,
             const char *old_iface)
{
	char newstr[INET6_ADDRSTRLEN];
	char oldstr[INET6_ADDRSTRLEN];
	char macstr[18];

	inet_ntop(new_af, new_ip, newstr, sizeof(newstr));
	inet_ntop(old_af, old_ip, oldstr, sizeof(oldstr));
	format_mac(mac, macstr, sizeof(macstr));

	if (strcmp(old_iface, new_iface) == 0)
		log_msg("moved station %s %s -> %s on %s",
		    macstr, oldstr, newstr, new_iface);
	else
		log_msg("moved station %s %s on %s -> %s on %s",
		    macstr, oldstr, old_iface, newstr, new_iface);
	if (!cfg.quiet)
		notify_moved(new_af, new_ip, new_iface, mac, old_af, old_ip,
		    old_iface);

	if (db_delete(old_af, old_ip, mac, old_iface))
		log_msg("dropped obsolete %s %s on %s",
		        oldstr, macstr, old_iface);

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

	inet_ntop(af, ip, ipstr, sizeof(ipstr));
	inet_ntop(other_af, other_ip, otherstr, sizeof(otherstr));
	log_msg("probe: %s still active on %s, device has multiple IPs "
	    "(also %s)", ipstr, iface, otherstr);
}

#define BOGON_CACHE_SIZE 128

struct bogon_slot {
	int     af;
	uint8_t ip[16];
	char    iface[32];
	time_t  last_notified;
};

static struct bogon_slot bogon_cache[BOGON_CACHE_SIZE];

#define BOGON_LOG_MAX    10   /* max bogon reports per window */
#define BOGON_LOG_WINDOW 10   /* seconds */

static time_t bogon_log_window_start;
static int    bogon_log_count;
static int    bogon_log_suppressed;

/*
 * Global rate cap for bogon reporting. The per-(af,ip,iface) cooldown does
 * not bound a flood of DISTINCT bogon sources (each is a fresh key), and
 * IPv6 gives an unlimited supply, so cap total reports per window as a
 * hard backstop against a log/fork flood. Applies even under -B 0.
 */
static int
bogon_log_allowed(time_t now)
{
	if (now < bogon_log_window_start ||
	    now - bogon_log_window_start >= BOGON_LOG_WINDOW) {
		bogon_log_window_start = now;
		bogon_log_count = 0;
		bogon_log_suppressed = 0;
	}
	if (bogon_log_count >= BOGON_LOG_MAX) {
		if (!bogon_log_suppressed) {
			log_msg("bogon reports rate-limited (>%d/%ds)",
			    BOGON_LOG_MAX, BOGON_LOG_WINDOW);
			bogon_log_suppressed = 1;
		}
		return 0;
	}
	bogon_log_count++;
	return 1;
}

static int
bogon_in_cooldown(int af, const uint8_t *ip, const char *iface, time_t now)
{
	int ilen = ip_len(af);

	for (int i = 0; i < BOGON_CACHE_SIZE; i++) {
		if (bogon_cache[i].last_notified == 0)
			continue;
		if (bogon_cache[i].af == af &&
		    memcmp(bogon_cache[i].ip, ip, ilen) == 0 &&
		    strcmp(bogon_cache[i].iface, iface) == 0)
			return now - bogon_cache[i].last_notified <
			    cfg.bogon_cooldown;
	}
	return 0;
}

/* Record that this bogon was reported now: refresh its slot, or insert
 * into an empty slot, or evict the oldest. Called only once both the
 * cooldown and the global cap have allowed the report, so a dropped
 * report never stamps the cooldown. */
static void
bogon_mark(int af, const uint8_t *ip, const char *iface, time_t now)
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
			bogon_cache[i].last_notified = now;
			return;
		}
		if (bogon_cache[i].last_notified < oldest_time) {
			oldest_time = bogon_cache[i].last_notified;
			oldest = i;
		}
	}

	int slot = (empty >= 0) ? empty : oldest;
	bogon_cache[slot].af = af;
	memset(bogon_cache[slot].ip, 0, sizeof(bogon_cache[slot].ip));
	memcpy(bogon_cache[slot].ip, ip, ilen);
	snprintf(bogon_cache[slot].iface, sizeof(bogon_cache[slot].iface),
	    "%s", iface);
	bogon_cache[slot].last_notified = now;
}

static void
handle_bogon(int af, const uint8_t *ip, const uint8_t *mac,
             const char *iface)
{
	char ipstr[INET6_ADDRSTRLEN];
	char macstr[18];

	time_t now = mono_now();

	/* Decide with both rate limits before mutating either, so a report
	 * dropped by the global cap does not stamp the per-address cooldown
	 * (which would silence a genuine bogon for the full -B period).
	 * Per-(af,ip,iface) cooldown suppresses repeats; -B 0 disables it. */
	if (cfg.bogon_cooldown != 0 && bogon_in_cooldown(af, ip, iface, now))
		return;

	/* Global backstop: a flood of DISTINCT bogon sources bypasses the
	 * per-key cooldown, so cap total reporting per window. */
	if (!bogon_log_allowed(now))
		return;

	if (cfg.bogon_cooldown != 0)
		bogon_mark(af, ip, iface, now);

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
	time_t old_last_seen = 0;
	int event;

	if (len < sizeof(struct arp_pkt))
		return;

	arp = (const struct arp_pkt *)pkt;

	/* validate: Ethernet + IPv4, correct lengths. Hardware type 6
	 * (IEEE 802) is accepted too: Linux, FreeBSD and NetBSD update
	 * their caches from it on Ethernet, so it can poison them */
	if (ntohs(arp->htype) != ARPHRD_ETHER &&
	    ntohs(arp->htype) != ARPHRD_IEEE802)
		return;
	if (ntohs(arp->ptype) != ETHERTYPE_IP)
		return;
	if (arp->hlen != 6 || arp->plen != 4)
		return;
	/* hosts only take requests and replies into their cache */
	if (ntohs(arp->oper) != ARPOP_REQUEST &&
	    ntohs(arp->oper) != ARPOP_REPLY)
		return;

	/* hosts drop ARP for a multicast target before looking at the
	 * sender. ARP for a loopback target is kept: hosts with
	 * route_localnet set, as Kubernetes nodes have, take it */
	if ((arp->tpa[0] & 0xf0) == 0xe0)
		return;

	/* skip ARP probes (sender IP 0.0.0.0) */
	if (is_zero_ip4(arp->spa))
		return;

	/* skip multicast and limited broadcast sender IPs: hosts give them
	 * a fixed entry that ARP never changes. 240/4 is kept, as hosts use
	 * it as unicast. A broadcast or multicast sender MAC is kept too:
	 * hosts accept it, which turns the victim's unicast traffic into
	 * broadcast anyone can read */
	if ((arp->spa[0] & 0xf0) == 0xe0 ||
	    (arp->spa[0] == 255 && arp->spa[1] == 255 &&
	    arp->spa[2] == 255 && arp->spa[3] == 255))
		return;

	/* an address already recorded on this interface with this MAC
	 * is not a bogon (see parse_ndp) */
	if (!db_known(AF_INET, arp->spa, arp->sha, iface) &&
	    !capture_is_local_fresh(iface, AF_INET, arp->spa)) {
		if (!capture_is_local_any(AF_INET, arp->spa))
			handle_bogon(AF_INET, arp->spa, arp->sha, iface);
		return;
	}

	event = db_update(AF_INET, arp->spa, arp->sha, iface, old_mac,
	                  &old_last_seen);
	if (cfg.probe)
		probe_mark_seen(AF_INET, arp->spa, arp->sha, iface);
	if (event)
		handle_event(event, AF_INET, arp->spa, arp->sha,
		             old_mac, iface, old_last_seen);
}

/*
 * Check the options of an ND message and find its first link-layer
 * address option of want_type (1 Source, 2 Target), setting *lla to the
 * address, or to NULL if there is none. Returns 0 when hosts drop the
 * whole message: an option of length 0 or running past the end, or the
 * wanted option not 8 bytes long, its size for an Ethernet address.
 */
static int
ndp_lladdr_opt(const u_char *opts, size_t opts_len, uint8_t want_type,
               const uint8_t **lla)
{
	size_t off = 0;

	*lla = NULL;
	while (off < opts_len) {
		size_t olen;

		if (opts_len - off < 2)
			return 0;
		olen = (size_t)opts[off + 1] * 8;	/* in units of 8 bytes */
		if (olen == 0 || olen > opts_len - off)
			return 0;
		if (opts[off] == want_type && *lla == NULL) {
			if (olen != 8)
				return 0;
			*lla = opts + off + 2;
		}
		off += olen;
	}
	return 1;
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
	int short_logged = 0;

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
			uint32_t preferred = read_u32_be(opts + off + 8);
			const uint8_t *prefix = opts + off + 16;

			/* require the on-link (L) flag, for withdrawal too: a
			 * PIO without it must not change what is known to be
			 * on-link (RFC 4861 6.3.4) */
			if (!(flags & 0x80))
				goto next;
			/* hosts ignore the whole option, withdrawal included,
			 * when its preferred lifetime exceeds the valid one
			 * (RFC 4862 5.5.3) */
			if (preferred > valid)
				goto next;
			if (prefix_len == 0 || prefix_len > 128)
				goto next;

			/* ignore implausibly short on-link prefixes. real
			 * prefixes are /64 (SLAAC) or a site prefix at most.
			 * a rogue RA could otherwise suppress bogon detection
			 * across a huge slice of the address space */
			if (prefix_len < LEARNED_MIN_PREFIX6) {
				char pfxstr[INET6_ADDRSTRLEN];

				/* one line per RA: a single frame can carry
				 * dozens of such options */
				if (short_logged)
					goto next;
				short_logged = 1;
				inet_ntop(AF_INET6, prefix, pfxstr,
				    sizeof(pfxstr));
				log_msg("ignoring RA prefix %s/%u on %s: "
				    "shorter than /%d",
				    pfxstr, prefix_len, iface,
				    LEARNED_MIN_PREFIX6);
				goto next;
			}

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
				/* a prefix the host itself has configured
				 * is expected: log it, but only mail about
				 * prefixes that are new to this link, so a
				 * restart does not re-announce every one */
				if (!cfg.quiet &&
				    !capture_prefix_configured(iface,
				    AF_INET6, prefix, prefix_len))
					notify_ra_learned(iface, prefix,
					    prefix_len, router_src, valid);
			} else if (added == 2) {
				char pfxstr[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, prefix, pfxstr,
				    sizeof(pfxstr));
				log_msg("withdrawn prefix %s/%u on %s",
				    pfxstr, prefix_len, iface);
			}
		}

next:
		off += olen;
	}
}

/*
 * Check the options of the hop-by-hop or destination options header at
 * off, hlen bytes long, as Linux does: padding of 7 bytes at most, made
 * of zeros, at most 8 other options, a Router Alert of 2 bytes, and no
 * unknown option whose type says to discard the packet. Returns 0 when
 * hosts drop it. Checks that depend on the kernel version or settings
 * (IOAM, CALIPSO) are left out: a host that takes the packet must not
 * be missed.
 */
static int
ip6_opts_ok(const u_char *pkt, size_t off, size_t hlen, int hopopts)
{
	size_t i = off + 2, end = off + hlen, olen;
	int padlen = 0, count = 0;

	while (i < end) {
		if (pkt[i] == IP6OPT_PAD1) {
			if (++padlen > 7)
				return 0;
			i++;
			continue;
		}
		if (end - i < 2)
			return 0;
		olen = (size_t)pkt[i + 1] + 2;
		if (olen > end - i)
			return 0;
		if (pkt[i] == IP6OPT_PADN) {
			padlen += (int)olen;
			if (padlen > 7)
				return 0;
			for (size_t j = 2; j < olen; j++)
				if (pkt[i + j] != 0)
					return 0;
		} else {
			if (++count > 8)
				return 0;
			if (hopopts && pkt[i] == IP6OPT_ROUTER_ALERT &&
			    olen != 4)
				return 0;
			/* the two high bits of the type: 00 skips an
			 * unknown option, the others drop the packet */
			if ((pkt[i] >> 6) != 0)
				return 0;
			padlen = 0;
		}
		i += olen;
	}
	return 1;
}

static void
parse_ndp(const u_char *pkt, size_t len, const char *iface,
          const struct ether_header *eh)
{
	struct ip6_hdr ip6;
	const uint8_t *icmp, *src, *dst;
	uint8_t type, nxt, want;
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

	/* copy the IPv6 header into an aligned local: pkt sits at
	 * Ethernet payload offset 14, so overlaying a struct ip6_hdr
	 * on it would be misaligned and dereferencing it is undefined */
	memcpy(&ip6, pkt, sizeof(ip6));

	/* Parse the IPv6 payload only. Hosts ignore the bytes after it,
	 * so an option placed there must not be read, and they drop a
	 * packet longer than its frame. A zero length marks a jumbogram,
	 * which ND never is. */
	if (ntohs(ip6.ip6_plen) == 0 ||
	    ntohs(ip6.ip6_plen) > len - sizeof(struct ip6_hdr))
		return;
	len = sizeof(struct ip6_hdr) + ntohs(ip6.ip6_plen);

	/* Hosts drop, before any ND processing, a packet of another IP
	 * version, one from or to the loopback address, one from a
	 * multicast address, and one to :: or to a multicast address of
	 * scope 0 or 1, which never leaves a node (RFC 4291 2.5.3, 2.7) */
	src = (const uint8_t *)&ip6.ip6_src;
	dst = (const uint8_t *)&ip6.ip6_dst;
	if ((ip6.ip6_vfc & 0xf0) != 0x60 || is_loopback_ip6(src) ||
	    is_loopback_ip6(dst) || src[0] == 0xff || is_zero_ip6(dst) ||
	    (dst[0] == 0xff && (dst[1] & 0x0f) <= 1))
		return;

	/* Step over hop-by-hop, routing and destination options headers:
	 * hosts process ND messages placed behind them, a known way past
	 * RA-Guard, so they must be seen here too. Linux takes any number
	 * of them, so walk them all; each is at least 8 bytes, which bounds
	 * the walk by the frame length. ND must not be fragmented (RFC
	 * 6980), so a fragment header ends the walk. */
	nxt = ip6.ip6_nxt;
	icmp_off = sizeof(struct ip6_hdr);
	while (nxt == IPPROTO_HOPOPTS || nxt == IPPROTO_ROUTING ||
	    nxt == IPPROTO_DSTOPTS) {
		size_t hlen;

		if (len < icmp_off + 2)
			return;
		hlen = ((size_t)pkt[icmp_off + 1] + 1) * 8;
		if (len < icmp_off + hlen)
			return;
		/* Hosts drop the packet when a hop-by-hop header is not
		 * the first, or its options or those of a destination
		 * header fail ip6_opts_ok(). A routing header must have no
		 * segments left and come in a unicast frame and packet;
		 * its type is not checked, as a host may have segment
		 * routing enabled. */
		if (nxt == IPPROTO_ROUTING) {
			if (pkt[icmp_off + 3] != 0 || dst[0] == 0xff ||
			    (eh->ether_dhost[0] & 0x01))
				return;
		} else if ((nxt == IPPROTO_HOPOPTS &&
		    icmp_off != sizeof(struct ip6_hdr)) ||
		    !ip6_opts_ok(pkt, icmp_off, hlen,
		    nxt == IPPROTO_HOPOPTS))
			return;
		nxt = pkt[icmp_off];
		icmp_off += hlen;
	}
	if (nxt != IPPROTO_ICMPV6)
		return;
	if (len < icmp_off + 4)
		return;

	icmp = pkt + icmp_off;
	icmp_len = len - icmp_off;
	type = icmp[0];

	/* RFC 4861 6.1.1, 6.1.2, 7.1.1, 7.1.2, 8.1: valid RS, RA, NS, NA
	 * and Redirect carry hop limit 255. A lower value proves the packet
	 * crossed a router, so drop it to keep off-link spoofed traffic out
	 * of the database and the learned prefixes */
	if (ip6.ip6_hlim != 255)
		return;

	/* Hosts also drop ND messages with a code other than 0 (same RFC
	 * sections) or a bad checksum, so these must not change an entry
	 * either. Other ICMPv6 types are not ND and need no checksum. */
	if (type < ND_ROUTER_SOLICIT || type > ND_REDIRECT ||
	    icmp[1] != 0 ||
	    icmp6_checksum(src, dst, icmp, icmp_len) != 0)
		return;

	if (type == ND_ROUTER_ADVERT) {
		/* a valid Router Advertisement also has a link-local
		 * source (RFC 4861 6.1.2) */
		if (!IS_LINKLOCAL6(src))
			return;
		if (icmp_len < 16)
			return;
		/* hosts cache the router's address and Source LLA from
		 * the RA itself, so check them like a neighbor's: a forged
		 * RA would otherwise take over the gateway unnoticed */
		ip_addr = src;
		opts = icmp + 16;
		opts_len = icmp_len - 16;
		want = 1;
	} else if (type == ND_ROUTER_SOLICIT) {
		/* RS: type(1) + code(1) + cksum(2) + reserved(4) + opts.
		 * Routers cache the solicitor's Source LLA from it */
		if (icmp_len < 8)
			return;
		ip_addr = src;
		opts = icmp + 8;
		opts_len = icmp_len - 8;
		want = 1;
	} else if (type == ND_NEIGHBOR_ADVERT) {
		/* NA: type(1) + code(1) + cksum(2) + flags(4) + target(16) + opts */
		if (icmp_len < 24)
			return;
		/* RFC 4861 7.1.2: an NA to a multicast address has no
		 * Solicited flag, and hosts drop one that has it */
		if (dst[0] == 0xff && (icmp[4] & 0x40))
			return;
		ip_addr = icmp + 8;  /* target address */
		opts = icmp + 24;
		opts_len = icmp_len - 24;
		want = 2;	/* Target Link-Layer Address */
	} else if (type == ND_NEIGHBOR_SOLICIT) {
		/* NS: type(1) + code(1) + cksum(2) + reserved(4) + target(16) + opts */
		if (icmp_len < 24)
			return;
		/* hosts drop an NS for a multicast target (RFC 4861 7.1.1),
		 * and only learn the solicitor's address from one for an
		 * address of theirs, which :: and ::1 never are */
		if (icmp[8] == 0xff || is_zero_ip6(icmp + 8) ||
		    is_loopback_ip6(icmp + 8))
			return;
		/* use source IP from IPv6 header */
		ip_addr = src;
		opts = icmp + 24;
		opts_len = icmp_len - 24;
		want = 1;	/* Source Link-Layer Address */
	} else if (type == ND_REDIRECT) {
		/* Redirect: type(1) + code(1) + cksum(2) + reserved(4) +
		 * target(16) + destination(16) + opts. Hosts store its
		 * Target LLA in the neighbour cache entry of the target (RFC
		 * 4861 8.3), so a forged one sends traffic to another MAC:
		 * record the target like an NA's. RFC 4861 8.1: the source is
		 * link-local, the destination is not multicast, and the
		 * target is a link-local router or the destination itself */
		if (!IS_LINKLOCAL6(src))
			return;
		if (icmp_len < 40 || icmp[24] == 0xff)
			return;
		ip_addr = icmp + 8;
		if (!IS_LINKLOCAL6(ip_addr) &&
		    memcmp(ip_addr, icmp + 24, 16) != 0)
			return;
		opts = icmp + 40;
		opts_len = icmp_len - 40;
		want = 2;	/* Target Link-Layer Address */
	} else {
		return;
	}

	if (!ndp_lladdr_opt(opts, opts_len, want, &mac))
		return;

	/* an RA that passed the checks above is one hosts process */
	if (type == ND_ROUTER_ADVERT)
		parse_ra(icmp, icmp_len, iface, src);

	/* Fall back to Ethernet source MAC if NDP option is missing. Not
	 * for a Redirect: it comes from the router, not from the target,
	 * and without the option hosts learn no address for the target */
	if (!mac) {
		if (type == ND_REDIRECT)
			return;
		mac = eh->ether_shost;
	}

	/* skip multicast IPs (ff00::/8) */
	if (ip_addr[0] == 0xff)
		return;

	/* skip the unspecified address: an NS or RS from :: (a DAD probe,
	 * or a host without an address yet), or an NA whose target is ::.
	 * An NA from :: is checked like any other, as hosts take its
	 * Target LLA for the target */
	if (is_zero_ip6(ip_addr))
		return;

	/* an address already recorded on this interface with this MAC
	 * is not a bogon: after a restart the RA-learned prefix that made
	 * it local is only known again once the router re-advertises it */
	if (!db_known(AF_INET6, ip_addr, mac, iface) &&
	    !capture_is_local_fresh(iface, AF_INET6, ip_addr)) {
		if (!capture_is_local_any(AF_INET6, ip_addr))
			handle_bogon(AF_INET6, ip_addr, mac, iface);
		return;
	}

	/* for NA, use the target address; for NS, RS and RA, the source */
	event = db_update(AF_INET6, ip_addr, mac, iface, old_mac,
	                  &old_last_seen);
	if (cfg.probe)
		probe_mark_seen(AF_INET6, ip_addr, mac, iface);
	if (event)
		handle_event(event, AF_INET6, ip_addr, mac, old_mac, iface,
		             old_last_seen);
}

void
parse_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	const char *iface = (const char *)user;
	const struct ether_header *eh;
	static _Alignas(8) u_char frame[SNAP_LEN];
	uint16_t etype;
	size_t len = hdr->caplen, off;

	if (len < sizeof(struct ether_header) || len > sizeof(frame))
		return;

	/* Parse a private copy, static as a whole frame is too large for
	 * the stack. On Linux the capture buffer is a ring shared with the
	 * kernel, and a forked notification child would otherwise read
	 * addresses from a slot the kernel has reused. */
	memcpy(frame, pkt, len);
	pkt = frame;

	eh = (const struct ether_header *)pkt;
	etype = ntohs(eh->ether_type);
	off = sizeof(struct ether_header);

	/* An 802.1Q or 802.1ad priority tag (VLAN ID 0) marks untagged
	 * traffic with a priority only. Linux strips any number of them and
	 * processes the ARP or ND inside, so unwrap them all; each is 4
	 * bytes, which bounds the loop by the frame length. Other VLAN IDs
	 * belong to the VLAN subinterfaces. */
	while (etype == ETHERTYPE_VLAN || etype == ETHERTYPE_8021AD) {
		if (len < off + 4 || ((pkt[off] << 8 | pkt[off + 1]) & 0x0fff))
			return;
		etype = (uint16_t)(pkt[off + 2] << 8 | pkt[off + 3]);
		off += 4;
	}

	/* An ND message cut short by the snap length cannot be checked: its
	 * checksum covers all of it, and the part cut off may hold the
	 * option with the real link-layer address. An ARP message is whole
	 * at the start of the frame, whatever follows it. */
	if (etype == ETHERTYPE_ARP)
		parse_arp(pkt + off, len - off, iface);
	else if (etype == ETHERTYPE_IPV6 && hdr->caplen >= hdr->len)
		parse_ndp(pkt + off, len - off, iface, eh);
}
