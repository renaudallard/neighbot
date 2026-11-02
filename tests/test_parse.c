/*
 * Test harness for parse_packet().
 * Feeds known ARP and NDP packets through the parser, then frees the DB.
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "../neighbot.h"
#include "../db.h"
#include "../parse.h"
#include "nd_cksum.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

/* stubs. capture_is_local_fresh returns stub_local (1 by default) so
 * packets are processed unless a test makes addresses foreign */
int stub_local = 1;

int
capture_is_local_fresh(const char *iface, int af, const uint8_t *ip)
{
	(void)iface; (void)af; (void)ip;
	return stub_local;
}

int
capture_is_local_any(int af, const uint8_t *ip)
{
	(void)af; (void)ip;
	return stub_local;
}

int
capture_prefix_configured(const char *iface, int af, const uint8_t *prefix,
    int prefix_len)
{
	(void)iface; (void)af; (void)prefix; (void)prefix_len;
	return 0;
}

int
capture_is_own_ip(int af, const uint8_t *ip)
{
	(void)af; (void)ip;
	return 0;
}

/* RA-capture stub: record the most recent learned prefix for assertions */
int      ra_learned_calls;
int      ra_withdraw_calls;
char     ra_learned_iface[32];
int      ra_learned_af;
uint8_t  ra_learned_addr[16];
int      ra_learned_prefix_len;
uint32_t ra_learned_lifetime;

int
capture_add_learned_subnet(const char *iface, int af,
    const uint8_t *addr, int prefix_len, uint32_t lifetime_sec)
{
	/* mimic the real function: a zero lifetime is a withdrawal,
	 * which never learns a prefix (here it finds nothing to drop) */
	if (lifetime_sec == 0) {
		ra_withdraw_calls++;
		return -1;
	}
	ra_learned_calls++;
	snprintf(ra_learned_iface, sizeof(ra_learned_iface), "%s", iface);
	ra_learned_af = af;
	memcpy(ra_learned_addr, addr, 16);
	ra_learned_prefix_len = prefix_len;
	ra_learned_lifetime = lifetime_sec;
	return 1;
}

int probe_schedule_calls;

void probe_schedule(int af, const uint8_t *ip, const uint8_t *mac,
    int new_af, const uint8_t *new_ip, const char *new_iface,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)new_af; (void)new_ip;
  (void)new_iface; (void)iface;
  probe_schedule_calls++; }

void probe_mark_seen(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)iface; }

int notify_new_calls;

void notify_new(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)iface; notify_new_calls++; }

int notify_changed_calls;

void notify_changed(int af, const uint8_t *ip, const uint8_t *mac,
    const uint8_t *old_mac, const char *iface, time_t prev_seen)
{ (void)af; (void)ip; (void)mac; (void)old_mac; (void)iface; (void)prev_seen;
  notify_changed_calls++; }

void notify_flipflop(int af, const uint8_t *ip, const uint8_t *mac,
    const uint8_t *old_mac, const char *iface, time_t prev_seen)
{ (void)af; (void)ip; (void)mac; (void)old_mac; (void)iface; (void)prev_seen; }

int notify_bogon_calls;

void notify_bogon(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)iface; notify_bogon_calls++; }

void notify_reappeared(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface, time_t prev_seen)
{ (void)af; (void)ip; (void)mac; (void)iface; (void)prev_seen; }

void notify_moved(int new_af, const uint8_t *new_ip, const char *new_iface,
    const uint8_t *mac, int old_af, const uint8_t *old_ip,
    const char *old_iface)
{ (void)new_af; (void)new_ip; (void)new_iface; (void)mac; (void)old_af;
  (void)old_ip; (void)old_iface; }

int notify_storm_calls;
int notify_storm_fail;   /* number of storm alerts to drop */

int notify_storm(int af, const uint8_t *ip, const uint8_t *mac_a,
    const uint8_t *mac_b, const char *iface)
{ (void)af; (void)ip; (void)mac_a; (void)mac_b; (void)iface;
  notify_storm_calls++;
  if (notify_storm_fail > 0) { notify_storm_fail--; return 0; }
  return 1; }

void notify_ra_learned(const char *iface, const uint8_t *prefix,
    int prefix_len, const uint8_t *router, uint32_t lifetime)
{ (void)iface; (void)prefix; (void)prefix_len; (void)router; (void)lifetime; }

/* feed a frame as captured, without touching its ICMPv6 checksum */
static void
feed_raw(const char *iface, const uint8_t *pkt, size_t len)
{
	struct pcap_pkthdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = len;
	hdr.len    = len;
	parse_packet((u_char *)iface, &hdr, pkt);
}

/* feed a frame with its ICMPv6 checksum set, as the test frames are
 * built with a zero checksum */
static void
feed_on(const char *iface, const uint8_t *pkt, size_t len)
{
	static uint8_t buf[SNAP_LEN];

	if (len > sizeof(buf)) {
		feed_raw(iface, pkt, len);
		return;
	}
	memcpy(buf, pkt, len);
	nd_fix_cksum(buf, len);
	feed_raw(iface, buf, len);
}

static void
feed(const uint8_t *pkt, size_t len)
{
	feed_on("test0", pkt, len);
}

static void build_na(uint8_t *, const uint8_t *, const uint8_t *);

/* valid ARP request: 192.168.1.100 -> 192.168.1.1 */
static void
test_arp_request(void)
{
	uint8_t pkt[42];

	memset(pkt, 0, sizeof(pkt));

	/* Ethernet header */
	memset(pkt, 0xff, 6);                        /* dst: broadcast */
	pkt[6] = 0x00; pkt[7] = 0x11; pkt[8] = 0x22;
	pkt[9] = 0x33; pkt[10] = 0x44; pkt[11] = 0x55; /* src MAC */
	pkt[12] = 0x08; pkt[13] = 0x06;              /* ethertype: ARP */

	/* ARP payload */
	pkt[14] = 0x00; pkt[15] = 0x01;              /* htype: Ethernet */
	pkt[16] = 0x08; pkt[17] = 0x00;              /* ptype: IPv4 */
	pkt[18] = 6;                                  /* hlen */
	pkt[19] = 4;                                  /* plen */
	pkt[20] = 0x00; pkt[21] = 0x01;              /* oper: request */

	/* sha */
	pkt[22] = 0x00; pkt[23] = 0x11; pkt[24] = 0x22;
	pkt[25] = 0x33; pkt[26] = 0x44; pkt[27] = 0x55;

	/* spa: 192.168.1.100 */
	pkt[28] = 192; pkt[29] = 168; pkt[30] = 1; pkt[31] = 100;

	/* tha: zero */
	/* tpa: 192.168.1.1 */
	pkt[38] = 192; pkt[39] = 168; pkt[40] = 1; pkt[41] = 1;

	feed(pkt, sizeof(pkt));
}

/* valid ARP reply: 10.0.0.1 */
static void
test_arp_reply(void)
{
	uint8_t pkt[42];

	memset(pkt, 0, sizeof(pkt));

	/* Ethernet header */
	pkt[0] = 0x00; pkt[1] = 0x11; pkt[2] = 0x22;
	pkt[3] = 0x33; pkt[4] = 0x44; pkt[5] = 0x55;   /* dst */
	pkt[6] = 0xaa; pkt[7] = 0xbb; pkt[8] = 0xcc;
	pkt[9] = 0xdd; pkt[10] = 0xee; pkt[11] = 0xff;  /* src */
	pkt[12] = 0x08; pkt[13] = 0x06;

	/* ARP */
	pkt[14] = 0x00; pkt[15] = 0x01;
	pkt[16] = 0x08; pkt[17] = 0x00;
	pkt[18] = 6; pkt[19] = 4;
	pkt[20] = 0x00; pkt[21] = 0x02;              /* oper: reply */

	/* sha */
	pkt[22] = 0xaa; pkt[23] = 0xbb; pkt[24] = 0xcc;
	pkt[25] = 0xdd; pkt[26] = 0xee; pkt[27] = 0xff;

	/* spa: 10.0.0.1 */
	pkt[28] = 10; pkt[29] = 0; pkt[30] = 0; pkt[31] = 1;

	/* tha */
	pkt[32] = 0x00; pkt[33] = 0x11; pkt[34] = 0x22;
	pkt[35] = 0x33; pkt[36] = 0x44; pkt[37] = 0x55;

	/* tpa: 10.0.0.2 */
	pkt[38] = 10; pkt[39] = 0; pkt[40] = 0; pkt[41] = 2;

	feed(pkt, sizeof(pkt));
}

/* valid NDP Neighbor Advertisement (type 136) for 2001:db8::1 */
static void
test_ndp_na(void)
{
	uint8_t pkt[86];

	memset(pkt, 0, sizeof(pkt));

	/* Ethernet header */
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[2] = 0x00;
	pkt[3] = 0x00; pkt[4] = 0x00; pkt[5] = 0x01;   /* dst: multicast */
	pkt[6] = 0x02; pkt[7] = 0x11; pkt[8] = 0x22;
	pkt[9] = 0x33; pkt[10] = 0x44; pkt[11] = 0x55;  /* src MAC */
	pkt[12] = 0x86; pkt[13] = 0xdd;                  /* ethertype: IPv6 */

	/* IPv6 header */
	pkt[14] = 0x60;                                  /* version 6 */
	/* payload length: 32 (24 ICMPv6 + 8 option) */
	pkt[18] = 0x00; pkt[19] = 32;
	pkt[20] = 58;                                    /* next header: ICMPv6 */
	pkt[21] = 255;                                   /* hop limit */

	/* src: 2001:db8::1 */
	pkt[22] = 0x20; pkt[23] = 0x01; pkt[24] = 0x0d; pkt[25] = 0xb8;
	pkt[37] = 0x01;

	/* dst: ff02::1 */
	pkt[38] = 0xff; pkt[39] = 0x02;
	pkt[53] = 0x01;

	/* ICMPv6 NA: type=136, code=0, cksum=0 (ignored by parser) */
	pkt[54] = 136;
	/* flags: S=1, O=1 */
	pkt[58] = 0x60;

	/* target: 2001:db8::1 */
	pkt[62] = 0x20; pkt[63] = 0x01; pkt[64] = 0x0d; pkt[65] = 0xb8;
	pkt[77] = 0x01;

	/* NDP option: Target LLA (type=2, len=1 = 8 bytes) */
	pkt[78] = 2;    /* type */
	pkt[79] = 1;    /* length in 8-octet units */
	pkt[80] = 0x02; pkt[81] = 0x11; pkt[82] = 0x22;
	pkt[83] = 0x33; pkt[84] = 0x44; pkt[85] = 0x55;

	feed(pkt, sizeof(pkt));
}

/* valid NDP Neighbor Solicitation (type 135) for 2001:db8::2 */
static void
test_ndp_ns(void)
{
	uint8_t pkt[86];

	memset(pkt, 0, sizeof(pkt));

	/* Ethernet header */
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[2] = 0xff;
	pkt[3] = 0x00; pkt[4] = 0x00; pkt[5] = 0x02;
	pkt[6] = 0x02; pkt[7] = 0xaa; pkt[8] = 0xbb;
	pkt[9] = 0xcc; pkt[10] = 0xdd; pkt[11] = 0xee;
	pkt[12] = 0x86; pkt[13] = 0xdd;

	/* IPv6 header */
	pkt[14] = 0x60;
	pkt[18] = 0x00; pkt[19] = 32;
	pkt[20] = 58;
	pkt[21] = 255;

	/* src: 2001:db8::2 */
	pkt[22] = 0x20; pkt[23] = 0x01; pkt[24] = 0x0d; pkt[25] = 0xb8;
	pkt[37] = 0x02;

	/* dst: solicited-node multicast */
	pkt[38] = 0xff; pkt[39] = 0x02;
	pkt[51] = 0x01; pkt[52] = 0xff;
	pkt[53] = 0x02;

	/* ICMPv6 NS: type=135 */
	pkt[54] = 135;

	/* target: 2001:db8::1 */
	pkt[62] = 0x20; pkt[63] = 0x01; pkt[64] = 0x0d; pkt[65] = 0xb8;
	pkt[77] = 0x01;

	/* NDP option: Source LLA (type=1, len=1) */
	pkt[78] = 1;
	pkt[79] = 1;
	pkt[80] = 0x02; pkt[81] = 0xaa; pkt[82] = 0xbb;
	pkt[83] = 0xcc; pkt[84] = 0xdd; pkt[85] = 0xee;

	feed(pkt, sizeof(pkt));
}

/* NDP NA without Target LLA option. MAC should fall back to Ethernet src */
static void
test_ndp_na_no_tlla(void)
{
	uint8_t pkt[78];

	memset(pkt, 0, sizeof(pkt));

	/* Ethernet header */
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[2] = 0x00;
	pkt[3] = 0x00; pkt[4] = 0x00; pkt[5] = 0x01;   /* dst: multicast */
	pkt[6] = 0x02; pkt[7] = 0xcc; pkt[8] = 0xdd;
	pkt[9] = 0xee; pkt[10] = 0x11; pkt[11] = 0x22;  /* src MAC */
	pkt[12] = 0x86; pkt[13] = 0xdd;                  /* ethertype: IPv6 */

	/* IPv6 header */
	pkt[14] = 0x60;                                  /* version 6 */
	/* payload length: 24 (ICMPv6 NA, no options) */
	pkt[18] = 0x00; pkt[19] = 24;
	pkt[20] = 58;                                    /* next header: ICMPv6 */
	pkt[21] = 255;                                   /* hop limit */

	/* src: 2001:db8::3 */
	pkt[22] = 0x20; pkt[23] = 0x01; pkt[24] = 0x0d; pkt[25] = 0xb8;
	pkt[37] = 0x03;

	/* dst: ff02::1 */
	pkt[38] = 0xff; pkt[39] = 0x02;
	pkt[53] = 0x01;

	/* ICMPv6 NA: type=136, code=0 */
	pkt[54] = 136;
	pkt[58] = 0x60;                                  /* flags: S=1, O=1 */

	/* target: 2001:db8::3 */
	pkt[62] = 0x20; pkt[63] = 0x01; pkt[64] = 0x0d; pkt[65] = 0xb8;
	pkt[77] = 0x03;

	/* no NDP options */

	feed(pkt, sizeof(pkt));
}

/* valid Router Advertisement with one Prefix Information Option.
 * Router source fe80::1, prefix 2001:db8::/64, L flag, 3600s lifetime. */
static void
test_ndp_ra(void)
{
	uint8_t pkt[102];

	memset(pkt, 0, sizeof(pkt));

	/* Ethernet */
	pkt[0]  = 0x33; pkt[1]  = 0x33; pkt[2]  = 0x00;
	pkt[3]  = 0x00; pkt[4]  = 0x00; pkt[5]  = 0x01;
	pkt[6]  = 0x02; pkt[7]  = 0x11; pkt[8]  = 0x22;
	pkt[9]  = 0x33; pkt[10] = 0x44; pkt[11] = 0x55;
	pkt[12] = 0x86; pkt[13] = 0xdd;

	/* IPv6 header */
	pkt[14] = 0x60;
	pkt[18] = 0x00; pkt[19] = 48;   /* payload: 16 RA + 32 PIO */
	pkt[20] = 58;                    /* next: ICMPv6 */
	pkt[21] = 255;                   /* hop limit */

	/* src: fe80::1 */
	pkt[22] = 0xfe; pkt[23] = 0x80;
	pkt[37] = 0x01;
	/* dst: ff02::1 */
	pkt[38] = 0xff; pkt[39] = 0x02;
	pkt[53] = 0x01;

	/* ICMPv6 RA fixed part */
	pkt[54] = 134;                   /* type */
	pkt[55] = 0;                     /* code */
	/* cksum (56..57), hop_limit (58), flags (59) */
	pkt[58] = 64;
	/* router lifetime (60..61) */
	pkt[60] = 0x07; pkt[61] = 0x08;  /* 1800s */
	/* reachable (62..65), retrans (66..69) zero */

	/* Prefix Information Option starts at pkt[70] */
	pkt[70] = 3;                     /* type */
	pkt[71] = 4;                     /* length (4 * 8 = 32 bytes) */
	pkt[72] = 64;                    /* prefix length */
	pkt[73] = 0x80;                  /* flags: L=1 */
	/* valid lifetime 3600 (big-endian) */
	pkt[74] = 0x00; pkt[75] = 0x00; pkt[76] = 0x0e; pkt[77] = 0x10;
	/* preferred lifetime 1800 */
	pkt[78] = 0x00; pkt[79] = 0x00; pkt[80] = 0x07; pkt[81] = 0x08;
	/* reserved (82..85) */
	/* prefix 2001:db8:: */
	pkt[86] = 0x20; pkt[87] = 0x01; pkt[88] = 0x0d; pkt[89] = 0xb8;

	int before = ra_learned_calls;
	feed(pkt, sizeof(pkt));
	if (ra_learned_calls != before + 1) {
		fprintf(stderr, "FAIL: RA did not trigger learned subnet\n");
		exit(1);
	}
	if (ra_learned_af != AF_INET6 ||
	    ra_learned_prefix_len != 64 ||
	    ra_learned_lifetime != 3600 ||
	    ra_learned_addr[0] != 0x20 || ra_learned_addr[3] != 0xb8 ||
	    strcmp(ra_learned_iface, "test0") != 0) {
		fprintf(stderr, "FAIL: RA learned subnet fields mismatch\n");
		exit(1);
	}
}

/* RA with L flag cleared should NOT trigger learning */
static void
test_ndp_ra_no_l_flag(void)
{
	uint8_t pkt[102];

	memset(pkt, 0, sizeof(pkt));
	pkt[0]  = 0x33; pkt[1]  = 0x33; pkt[5]  = 0x01;
	pkt[6]  = 0x02; pkt[11] = 0x55;
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = 48;
	pkt[20] = 58;
	pkt[21] = 255;
	pkt[22] = 0xfe; pkt[23] = 0x80; pkt[37] = 0x01;
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 134;
	pkt[70] = 3;
	pkt[71] = 4;
	pkt[72] = 64;
	pkt[73] = 0x00;                  /* flags: L=0 */
	pkt[77] = 0x3c;                  /* valid lifetime 60 */
	pkt[86] = 0x20; pkt[87] = 0x01; pkt[88] = 0x0d; pkt[89] = 0xb9;

	int before = ra_learned_calls;
	feed(pkt, sizeof(pkt));
	if (ra_learned_calls != before) {
		fprintf(stderr, "FAIL: RA without L flag triggered learn\n");
		exit(1);
	}
}

/* RA with zero valid-lifetime should NOT trigger learning */
static void
test_ndp_ra_zero_lifetime(void)
{
	uint8_t pkt[102];

	memset(pkt, 0, sizeof(pkt));
	pkt[0]  = 0x33; pkt[1]  = 0x33; pkt[5]  = 0x01;
	pkt[6]  = 0x02; pkt[11] = 0x55;
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = 48;
	pkt[20] = 58;
	pkt[21] = 255;
	pkt[22] = 0xfe; pkt[23] = 0x80; pkt[37] = 0x01;
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 134;
	pkt[70] = 3;
	pkt[71] = 4;
	pkt[72] = 64;
	pkt[73] = 0x80;                  /* L=1 */
	/* valid lifetime 0 */
	pkt[86] = 0x20; pkt[87] = 0x01; pkt[88] = 0x0d; pkt[89] = 0xba;

	int before = ra_learned_calls;
	int wbefore = ra_withdraw_calls;
	feed(pkt, sizeof(pkt));
	if (ra_learned_calls != before) {
		fprintf(stderr, "FAIL: RA with zero lifetime triggered learn\n");
		exit(1);
	}
	if (ra_withdraw_calls != wbefore + 1) {
		fprintf(stderr, "FAIL: RA with zero lifetime did not withdraw\n");
		exit(1);
	}
}

/* hosts ignore a prefix option whose preferred lifetime exceeds its
 * valid one, so it neither teaches nor withdraws a prefix */
static void
test_ndp_ra_bad_lifetimes(void)
{
	uint8_t pkt[102];
	int before = ra_learned_calls, wbefore = ra_withdraw_calls;

	memset(pkt, 0, sizeof(pkt));
	pkt[0]  = 0x33; pkt[1]  = 0x33; pkt[5]  = 0x01;
	pkt[6]  = 0x02; pkt[11] = 0x56;
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60; pkt[19] = 48; pkt[20] = 58; pkt[21] = 255;
	pkt[22] = 0xfe; pkt[23] = 0x80; pkt[37] = 0x56;
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 134;
	pkt[70] = 3; pkt[71] = 4; pkt[72] = 64; pkt[73] = 0x80;
	pkt[76] = 0x07; pkt[77] = 0x08;          /* valid 1800 */
	pkt[80] = 0x0e; pkt[81] = 0x10;          /* preferred 3600 */
	pkt[86] = 0x20; pkt[87] = 0x01; pkt[88] = 0x0d; pkt[89] = 0xbb;
	feed(pkt, sizeof(pkt));

	pkt[76] = pkt[77] = 0;                   /* a withdrawal */
	feed(pkt, sizeof(pkt));
	if (ra_learned_calls != before || ra_withdraw_calls != wbefore) {
		fprintf(stderr, "FAIL: prefix option with a preferred lifetime "
		    "above the valid one was used\n");
		exit(1);
	}
}

/* a zero-lifetime PIO without the L flag must not withdraw an on-link
 * prefix (RFC 4861 6.3.4) */
static void
test_ndp_ra_withdraw_no_l_flag(void)
{
	uint8_t pkt[102];

	memset(pkt, 0, sizeof(pkt));
	pkt[0]  = 0x33; pkt[1]  = 0x33; pkt[5]  = 0x01;
	pkt[6]  = 0x02; pkt[11] = 0x55;
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = 48;
	pkt[20] = 58;
	pkt[21] = 255;
	pkt[22] = 0xfe; pkt[23] = 0x80; pkt[37] = 0x01;
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 134;
	pkt[70] = 3;
	pkt[71] = 4;
	pkt[72] = 64;
	pkt[73] = 0x00;                  /* L=0 */
	/* valid lifetime 0 (withdrawal) */
	pkt[86] = 0x20; pkt[87] = 0x01; pkt[88] = 0x0d; pkt[89] = 0xba;

	int before = ra_learned_calls;
	int wbefore = ra_withdraw_calls;
	feed(pkt, sizeof(pkt));
	if (ra_learned_calls != before) {
		fprintf(stderr, "FAIL: zero-lifetime RA without L flag learned\n");
		exit(1);
	}
	if (ra_withdraw_calls != wbefore) {
		fprintf(stderr,
		    "FAIL: zero-lifetime RA without L flag withdrew\n");
		exit(1);
	}
}

/* NA with a hop limit below 255 must be dropped (RFC 4861 7.1.2) */
static void
test_ndp_hlim(void)
{
	uint8_t pkt[86];
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;   /* allow notify_new so the accept path is countable */

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	pkt[6] = 0x02; pkt[11] = 0x99;           /* src MAC */
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = 32;                            /* payload: 24 NA + 8 option */
	pkt[20] = 58;                            /* next header: ICMPv6 */
	pkt[21] = 255;                           /* hop limit */
	pkt[22] = 0x20;                          /* src non-zero */
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 136;                           /* NA */
	pkt[58] = 0x60;                          /* flags S=1 O=1 */
	pkt[62] = 0x20; pkt[63] = 0x01; pkt[64] = 0x0d; pkt[65] = 0xb8;
	pkt[77] = 0x11;                          /* target 2001:db8::11 */
	pkt[78] = 2; pkt[79] = 1;                /* Target LLA option */
	pkt[80] = 0x02; pkt[85] = 0x99;

	before = notify_new_calls;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: NA with hop limit 255 was rejected\n");
		exit(1);
	}

	/* same packet with hop limit 64 and a fresh target: must drop */
	pkt[21] = 64;
	pkt[77] = 0x22;                          /* target 2001:db8::22 */
	before = notify_new_calls;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before) {
		fprintf(stderr, "FAIL: NA with hop limit 64 was not dropped\n");
		exit(1);
	}

	cfg.quiet = saved_quiet;
}

/* three MACs taking turns on one IP: each event is "changed", and the
 * storm check must still stop the alerts */
static void
test_three_mac_storm(void)
{
	uint8_t pkt[42];
	int saved_quiet = cfg.quiet;

	cfg.quiet = 0;
	storm_reset();
	notify_changed_calls = notify_storm_calls = 0;

	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[12] = 0x08; pkt[13] = 0x06;
	pkt[15] = 0x01; pkt[16] = 0x08; pkt[18] = 6; pkt[19] = 4;
	pkt[21] = 0x01;
	pkt[28] = 10; pkt[29] = 9; pkt[30] = 9; pkt[31] = 9;
	pkt[38] = 10; pkt[39] = 9; pkt[40] = 9; pkt[41] = 1;

	for (int i = 0; i < 60; i++) {
		uint8_t last = (uint8_t)(1 + i % 3);

		pkt[6] = pkt[22] = 0x02;
		pkt[11] = pkt[27] = last;
		feed(pkt, sizeof(pkt));
	}

	if (notify_storm_calls != 1 ||
	    notify_changed_calls >= STORM_THRESHOLD) {
		fprintf(stderr, "FAIL: 3-MAC rotation: %d changed alerts, "
		    "%d storm alerts\n", notify_changed_calls,
		    notify_storm_calls);
		exit(1);
	}

	storm_reset();
	cfg.quiet = saved_quiet;
}

/* ARP reply for 10.0.0.1 from 02:00:00:00:00:<last> on iface */
static void
feed_gw_arp(const char *iface, uint8_t last)
{
	uint8_t pkt[42];

	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[6] = pkt[22] = 0x02;
	pkt[11] = pkt[27] = last;
	pkt[12] = 0x08; pkt[13] = 0x06;
	pkt[15] = 0x01; pkt[16] = 0x08; pkt[18] = 6; pkt[19] = 4;
	pkt[21] = 0x02;
	pkt[28] = 10; pkt[31] = 1;
	feed_on(iface, pkt, sizeof(pkt));
}

/* a storm for an address on one link must not silence a change of the
 * same address on another link, where it is a different station */
static void
test_storm_per_iface(void)
{
	int saved_quiet = cfg.quiet, before;

	cfg.quiet = 0;
	storm_reset();
	notify_storm_calls = 0;

	feed_gw_arp("vlan20", 0x0c);
	for (int i = 0; i < 8; i++)
		feed_gw_arp("vlan10", (i & 1) ? 0x0b : 0x0a);
	if (notify_storm_calls != 1) {
		fprintf(stderr, "FAIL: storm on vlan10: %d storm alerts\n",
		    notify_storm_calls);
		exit(1);
	}

	before = notify_changed_calls;
	feed_gw_arp("vlan20", 0x0d);
	if (notify_changed_calls != before + 1) {
		fprintf(stderr, "FAIL: storm on vlan10 silenced a change "
		    "on vlan20\n");
		exit(1);
	}

	storm_reset();
	cfg.quiet = saved_quiet;
}

/* Neighbor Advertisement for target, Target LLA option set to mac */
static void
feed_na_on(const char *iface, const uint8_t *mac, const char *target)
{
	uint8_t pkt[86];

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	memcpy(pkt + 6, mac, 6);
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = 32;                            /* payload: 24 NA + 8 option */
	pkt[20] = 58;
	pkt[21] = 255;
	inet_pton(AF_INET6, target, pkt + 22);   /* src = target */
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 136;
	pkt[58] = 0x20;                          /* O flag */
	inet_pton(AF_INET6, target, pkt + 62);
	pkt[78] = 2; pkt[79] = 1;
	memcpy(pkt + 80, mac, 6);
	feed_on(iface, pkt, sizeof(pkt));
}

static void
feed_na(const uint8_t *mac, const char *target)
{
	feed_na_on("test0", mac, target);
}

/* the same MAC with different non-EUI-64 link-locals on two links is
 * two stations, not an address rotation */
static void
test_linklocal_two_links(void)
{
	const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x0c };
	int saved_quiet = cfg.quiet;
	int before = notify_new_calls;

	cfg.quiet = 0;
	feed_na_on("vlan10", mac, "fe80::1a2b:3c4d:5e6f:7081");
	feed_na_on("vlan20", mac, "fe80::9aab:bccd:deef:f001");
	if (notify_new_calls != before + 2) {
		fprintf(stderr, "FAIL: link-locals on two links gave %d new "
		    "station alerts, want 2\n", notify_new_calls - before);
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* A spoofed new temporary address from the owner's MAC must not clear
 * the owner's idle address, or another MAC with a temporary address in
 * the same /64 could take it over as a "new temporary" without any
 * changed alert. */
static void
test_temp_takeover(void)
{
	const uint8_t owner[6] = { 0x02, 0, 0, 0, 0, 0x0a };
	const uint8_t attacker[6] = { 0x02, 0, 0, 0, 0, 0x0b };
	const char *path = "tmp/test_parse_takeover.csv";
	int saved_quiet = cfg.quiet;
	FILE *fp;

	mkdir("tmp", 0755);
	fp = fopen(path, "w");
	if (!fp) {
		perror(path);
		exit(1);
	}
	/* owner's address and the attacker's temporary, both long idle */
	fprintf(fp, "fd00::aaaa:1,02:00:00:00:00:0a,test0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00\n"
	    "fd00::bbbb:1,02:00:00:00:00:0b,test0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00\n");
	fclose(fp);

	db_free();
	db_init();
	if (db_load(path) != 2) {
		fprintf(stderr, "FAIL: takeover fixture did not load\n");
		exit(1);
	}
	unlink(path);

	cfg.quiet = 0;
	notify_changed_calls = 0;
	feed_na(owner, "fd00::aaaa:2");          /* spoofed rotation */
	feed_na(attacker, "fd00::aaaa:1");       /* claim the owner's IP */
	if (notify_changed_calls != 1) {
		fprintf(stderr, "FAIL: takeover after a spoofed rotation "
		    "raised %d changed alerts, want 1\n",
		    notify_changed_calls);
		exit(1);
	}

	cfg.quiet = saved_quiet;
	db_free();
	db_init();
}

/* a storm alert dropped by the in-flight cap must not commit the
 * suppression; the next flip retries it */
static void
test_storm_alert_dropped(void)
{
	uint8_t pkt[42];
	int saved_quiet = cfg.quiet;

	cfg.quiet = 0;
	storm_reset();
	notify_storm_calls = 0;
	notify_storm_fail = 1;

	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[12] = 0x08; pkt[13] = 0x06;
	pkt[15] = 0x01; pkt[16] = 0x08; pkt[18] = 6; pkt[19] = 4;
	pkt[21] = 0x01;
	pkt[28] = 10; pkt[29] = 9; pkt[30] = 8; pkt[31] = 7;
	pkt[38] = 10; pkt[39] = 9; pkt[40] = 8; pkt[41] = 1;

	for (int i = 0; i < 20; i++) {
		pkt[6] = pkt[22] = 0x02;
		pkt[11] = pkt[27] = (uint8_t)(0x40 + i % 2);
		feed(pkt, sizeof(pkt));
	}

	if (notify_storm_calls != 2) {
		fprintf(stderr, "FAIL: dropped storm alert: %d storm calls, "
		    "want 2 (dropped one, then sent)\n", notify_storm_calls);
		exit(1);
	}

	notify_storm_fail = 0;
	storm_reset();
	cfg.quiet = saved_quiet;
}

/* a temporary address rotation probes the MAC's other addresses but
 * not the older temporaries it replaces, which would end as moved */
static void
test_temp_rotation_probes(void)
{
	const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x0d };
	int saved_probe = cfg.probe;

	cfg.probe = 1;
	feed_na(mac, "2001:db8:5::aaaa:1");      /* first temporary */
	feed_na(mac, "2001:db8:5::0:ff:fe00:d"); /* EUI-64 of mac */
	probe_schedule_calls = 0;
	feed_na(mac, "2001:db8:5::aaaa:2");      /* rotation */
	if (probe_schedule_calls != 1) {
		fprintf(stderr, "FAIL: temp rotation scheduled %d probes, "
		    "want 1 (the EUI-64 address only)\n",
		    probe_schedule_calls);
		exit(1);
	}

	/* a temporary in a ULA prefix next to the global one is not
	 * probed either: once expired it would be reported as moved */
	feed_na(mac, "fd00:5::bbbb:1");
	probe_schedule_calls = 0;
	feed_na(mac, "2001:db8:5::aaaa:3");      /* rotation */
	if (probe_schedule_calls != 1) {
		fprintf(stderr, "FAIL: temp rotation scheduled %d probes, "
		    "want 1 (not the ULA temporary)\n",
		    probe_schedule_calls);
		exit(1);
	}
	cfg.probe = saved_probe;
}

/* an address recorded under the same MAC is not a bogon when its prefix
 * is not (yet) known, e.g. after a restart before the next RA; another
 * MAC claiming it is */
static void
test_known_not_bogon(void)
{
	const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x0e };
	const uint8_t other[6] = { 0x02, 0, 0, 0, 0, 0x0f };
	int saved_quiet = cfg.quiet;

	cfg.quiet = 0;
	feed_na(mac, "2001:db8:7::1");
	stub_local = 0;
	notify_bogon_calls = 0;
	feed_na(mac, "2001:db8:7::1");
	if (notify_bogon_calls != 0) {
		fprintf(stderr, "FAIL: known station reported as bogon\n");
		exit(1);
	}
	feed_na(other, "2001:db8:7::1");
	if (notify_bogon_calls != 1) {
		fprintf(stderr, "FAIL: another MAC on a foreign address was "
		    "not reported as bogon\n");
		exit(1);
	}
	stub_local = 1;
	cfg.quiet = saved_quiet;
}

/* A frame cut short by the snap length: ARP is whole at its start and is
 * processed, but ND is not, as the cut may have taken the option with
 * the real link-layer address and its checksum cannot be checked */
static void
test_snap_truncated(void)
{
	struct pcap_pkthdr hdr;
	uint8_t pkt[86], tgt[16];
	uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x31 };
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;
	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[6] = pkt[22] = 0x02; pkt[11] = pkt[27] = 0x31;
	pkt[12] = 0x08; pkt[13] = 0x06;
	pkt[15] = 0x01; pkt[16] = 0x08; pkt[18] = 6; pkt[19] = 4;
	pkt[21] = 0x01;
	pkt[28] = 10; pkt[29] = 31; pkt[30] = 0; pkt[31] = 1;

	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = 42;
	hdr.len = 42 + 9000;
	before = notify_new_calls;
	parse_packet((u_char *)"test0", &hdr, pkt);
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: truncated ARP frame was dropped\n");
		exit(1);
	}

	inet_pton(AF_INET6, "2001:db8:9::31", tgt);
	build_na(pkt, tgt, mac);
	nd_fix_cksum(pkt, sizeof(pkt));
	hdr.caplen = sizeof(pkt);
	hdr.len = sizeof(pkt) + 100;
	parse_packet((u_char *)"test0", &hdr, pkt);
	if (db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: truncated NA was processed\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* hosts take ND from any frame their link carries, so an NA in a frame
 * over 9216 bytes, padded with unknown options, must be parsed whole */
static void
test_jumbo_frame(void)
{
	static uint8_t pkt[86 + 5 * 2040];
	uint8_t tgt[16];
	uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x50 };
	size_t plen = sizeof(pkt) - 54;

	inet_pton(AF_INET6, "2001:db8:9::50", tgt);
	build_na(pkt, tgt, mac);
	for (int i = 0; i < 5; i++) {
		pkt[86 + i * 2040] = 250;        /* unassigned type */
		pkt[87 + i * 2040] = 255;        /* 2040 bytes */
	}
	pkt[18] = (uint8_t)(plen >> 8);
	pkt[19] = (uint8_t)plen;
	feed(pkt, sizeof(pkt));
	if (!db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: NA in a %zu-byte frame was dropped\n",
		    sizeof(pkt));
		exit(1);
	}
}

/* ARP with hardware type 6 (IEEE 802) is processed like Ethernet */
static void
test_arp_hwtype6(void)
{
	uint8_t pkt[42];
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;
	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[6] = pkt[22] = 0x02; pkt[11] = pkt[27] = 0x32;
	pkt[12] = 0x08; pkt[13] = 0x06;
	pkt[15] = 0x06;                          /* hardware type 6 */
	pkt[16] = 0x08; pkt[18] = 6; pkt[19] = 4;
	pkt[21] = 0x02;
	pkt[28] = 10; pkt[29] = 32; pkt[30] = 0; pkt[31] = 1;

	before = notify_new_calls;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: ARP hardware type 6 was ignored\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* a known IP claimed by the broadcast MAC is reported as changed */
static void
test_broadcast_mac_claim(void)
{
	uint8_t pkt[42];
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;
	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[6] = pkt[22] = 0x02; pkt[11] = pkt[27] = 0x33;
	pkt[12] = 0x08; pkt[13] = 0x06;
	pkt[15] = 0x01; pkt[16] = 0x08; pkt[18] = 6; pkt[19] = 4;
	pkt[21] = 0x02;
	pkt[28] = 10; pkt[29] = 33; pkt[30] = 0; pkt[31] = 1;
	feed(pkt, sizeof(pkt));

	memset(pkt + 22, 0xff, 6);               /* sender MAC broadcast */
	before = notify_changed_calls;
	feed(pkt, sizeof(pkt));
	if (notify_changed_calls != before + 1) {
		fprintf(stderr, "FAIL: broadcast MAC claim not reported\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* RA or RS with a Source LLA option, no prefix */
static void
feed_rs_ra(int type, const char *src, const uint8_t *slla)
{
	uint8_t pkt[94];
	size_t fixed = (type == 134) ? 16 : 8;
	size_t len = 54 + fixed + 8;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	memcpy(pkt + 6, slla, 6);
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = (uint8_t)(fixed + 8);
	pkt[20] = 58;
	pkt[21] = 255;
	inet_pton(AF_INET6, src, pkt + 22);
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = (uint8_t)type;
	pkt[54 + fixed] = 1;                     /* Source LLA option */
	pkt[54 + fixed + 1] = 1;
	memcpy(pkt + 54 + fixed + 2, slla, 6);
	feed(pkt, len);
}

/* the RA source and Source LLA are recorded, so a forged RA taking over
 * the router's address is reported; RS sources are recorded too */
static void
test_ra_rs_lladdr(void)
{
	const uint8_t gw[6] = { 0x02, 0, 0, 0, 0, 0x41 };
	const uint8_t evil[6] = { 0x02, 0, 0, 0, 0, 0x42 };
	const uint8_t host[6] = { 0x02, 0, 0, 0, 0, 0x43 };
	int saved_quiet = cfg.quiet;
	int nbefore, cbefore;

	cfg.quiet = 0;
	nbefore = notify_new_calls;
	feed_rs_ra(134, "fe80::41", gw);
	feed_rs_ra(133, "2001:db8:8::43", host);
	if (notify_new_calls != nbefore + 2) {
		fprintf(stderr, "FAIL: RA/RS sources not recorded (%d)\n",
		    notify_new_calls - nbefore);
		exit(1);
	}
	cbefore = notify_changed_calls;
	feed_rs_ra(134, "fe80::41", evil);
	if (notify_changed_calls != cbefore + 1) {
		fprintf(stderr, "FAIL: forged RA for the router address "
		    "not reported\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* an NA behind a Destination Options header is processed */
static void
test_na_ext_header(void)
{
	uint8_t pkt[94];
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	pkt[6] = 0x02; pkt[11] = 0x44;
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = 40;                            /* 8 dstopts + 32 NA */
	pkt[20] = 60;                            /* next: dest options */
	pkt[21] = 255;
	inet_pton(AF_INET6, "2001:db8:9::44", pkt + 22);
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 58;                            /* next: ICMPv6 */
	pkt[55] = 0;                             /* 8 bytes */
	pkt[56] = 1; pkt[57] = 4;                /* PadN */
	pkt[62] = 136;                           /* NA */
	pkt[66] = 0x20;
	inet_pton(AF_INET6, "2001:db8:9::44", pkt + 70);
	pkt[86] = 2; pkt[87] = 1;
	pkt[88] = 0x02; pkt[93] = 0x44;

	before = notify_new_calls;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: NA behind a dest options header was "
		    "ignored\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* an NA behind 40 Destination Options headers is processed: Linux takes
 * any number of them, so a cap would let a forged NA through unseen */
static void
test_na_many_ext_headers(void)
{
	enum { NHDR = 40, PLEN = NHDR * 8 + 32 };
	uint8_t pkt[54 + PLEN];
	uint8_t *p = pkt + 54;
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	pkt[6] = 0x02; pkt[11] = 0x46;
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[18] = PLEN >> 8; pkt[19] = PLEN & 0xff;
	pkt[20] = 60;                            /* next: dest options */
	pkt[21] = 255;
	inet_pton(AF_INET6, "2001:db8:9::46", pkt + 22);
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	for (int i = 0; i < NHDR; i++, p += 8) {
		p[0] = (i < NHDR - 1) ? 60 : 58;    /* next header */
		p[2] = 1; p[3] = 4;                 /* PadN */
	}
	p[0] = 136;                              /* NA */
	p[4] = 0x20;
	inet_pton(AF_INET6, "2001:db8:9::46", p + 8);
	p[24] = 2; p[25] = 1;
	p[26] = 0x02; p[31] = 0x46;

	before = notify_new_calls;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: NA behind 40 dest options headers was "
		    "ignored\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* bytes after the IPv6 payload are not part of the packet: a Target LLA
 * option placed there is not used, and the Ethernet source is recorded;
 * a payload length past the end of the frame drops the packet */
static void
test_nd_payload_length(void)
{
	uint8_t pkt[86];
	uint8_t eth[6] = { 0x02, 0, 0, 0, 0, 0x48 };
	uint8_t fake[6] = { 0x02, 0, 0, 0, 0, 0x66 };
	uint8_t tgt[16];

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	memcpy(pkt + 6, eth, 6);
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60;
	pkt[19] = 24;                            /* NA without options */
	pkt[20] = 58; pkt[21] = 255;
	inet_pton(AF_INET6, "2001:db8:9::48", tgt);
	memcpy(pkt + 22, tgt, 16);
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 136; pkt[58] = 0x20;
	memcpy(pkt + 62, tgt, 16);
	pkt[78] = 2; pkt[79] = 1;                /* trailer: Target LLA */
	memcpy(pkt + 80, fake, 6);

	feed(pkt, sizeof(pkt));
	if (!db_known(AF_INET6, tgt, eth, "test0") ||
	    db_known(AF_INET6, tgt, fake, "test0")) {
		fprintf(stderr, "FAIL: option after the IPv6 payload was "
		    "used\n");
		exit(1);
	}

	/* a payload length longer than the frame */
	pkt[19] = 40;
	pkt[77] = tgt[15] = 0x49;                /* target 2001:db8:9::49 */
	feed(pkt, sizeof(pkt));
	if (db_known(AF_INET6, tgt, eth, "test0") ||
	    db_known(AF_INET6, tgt, fake, "test0")) {
		fprintf(stderr, "FAIL: IPv6 packet longer than its frame was "
		    "processed\n");
		exit(1);
	}
}

/* NA for target with Target LLA mac */
static void
build_na(uint8_t *pkt, const uint8_t *target, const uint8_t *mac)
{
	memset(pkt, 0, 86);
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	memcpy(pkt + 6, mac, 6);
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60; pkt[19] = 32; pkt[20] = 58; pkt[21] = 255;
	memcpy(pkt + 22, target, 16);
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 136; pkt[58] = 0x20;
	memcpy(pkt + 62, target, 16);
	pkt[78] = 2; pkt[79] = 1;
	memcpy(pkt + 80, mac, 6);
}

/* hosts drop ND messages with a non-zero code or a bad checksum, so
 * neither may change an entry */
static void
test_nd_code_and_checksum(void)
{
	uint8_t pkt[86], tgt[16];
	uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x4a };

	inet_pton(AF_INET6, "2001:db8:9::4a", tgt);

	build_na(pkt, tgt, mac);
	pkt[55] = 1;                             /* code 1 */
	feed(pkt, sizeof(pkt));
	if (db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: NA with code 1 was processed\n");
		exit(1);
	}

	build_na(pkt, tgt, mac);
	nd_fix_cksum(pkt, sizeof(pkt));
	pkt[56] ^= 0x55;                         /* break the checksum */
	feed_raw("test0", pkt, sizeof(pkt));
	if (db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: NA with a bad checksum was processed\n");
		exit(1);
	}

	pkt[56] ^= 0x55;
	feed_raw("test0", pkt, sizeof(pkt));
	if (!db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: NA with a good checksum was dropped\n");
		exit(1);
	}
}

/* hosts take the Target LLA of an NA sent from :: like any other, so
 * it must change the entry; an NS from :: is a DAD probe and records
 * nothing */
static void
test_na_unspecified_source(void)
{
	uint8_t pkt[86], tgt[16], zero[16];
	uint8_t real[6] = { 0x02, 0, 0, 0, 0, 0x4e };
	uint8_t evil[6] = { 0x02, 0, 0, 0, 0, 0x4f };
	int saved_quiet = cfg.quiet, before;

	cfg.quiet = 0;
	memset(zero, 0, sizeof(zero));
	inet_pton(AF_INET6, "2001:db8:9::4e", tgt);
	build_na(pkt, tgt, real);
	feed(pkt, sizeof(pkt));

	before = notify_changed_calls;
	build_na(pkt, tgt, evil);
	memset(pkt + 22, 0, 16);                 /* source :: */
	feed(pkt, sizeof(pkt));
	if (notify_changed_calls != before + 1 ||
	    !db_known(AF_INET6, tgt, evil, "test0")) {
		fprintf(stderr, "FAIL: NA from :: was not processed\n");
		exit(1);
	}

	/* a DAD probe: NS from :: for the target, without an option */
	build_na(pkt, tgt, real);
	memset(pkt + 22, 0, 16);
	pkt[19] = 24;
	pkt[54] = 135;
	pkt[58] = 0;
	feed(pkt, 78);
	if (db_known(AF_INET6, zero, real, "test0") ||
	    !db_known(AF_INET6, tgt, evil, "test0")) {
		fprintf(stderr, "FAIL: NS from :: changed the database\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* hosts drop an ND message whose options are malformed: an option of
 * length 0, or a link-layer address option that is not 8 bytes long. A
 * second Target LLA option is ignored, as hosts keep the first */
static void
test_nd_bad_options(void)
{
	uint8_t pkt[110], tgt[16];
	uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x4b };
	uint8_t dup[6] = { 0x02, 0, 0, 0, 0, 0x4c };
	int before;

	inet_pton(AF_INET6, "2001:db8:9::4b", tgt);

	/* Target LLA option 16 bytes long */
	memset(pkt, 0, sizeof(pkt));
	build_na(pkt, tgt, mac);
	pkt[19] = 40; pkt[79] = 2;
	feed(pkt, 94);
	if (db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: NA with a 16-byte Target LLA was "
		    "processed\n");
		exit(1);
	}

	/* an option of length 0 before the Target LLA option, which ends
	 * the walk and left the Ethernet source to be recorded */
	memset(pkt, 0, sizeof(pkt));
	build_na(pkt, tgt, mac);
	pkt[19] = 40;
	memmove(pkt + 86, pkt + 78, 8);
	memset(pkt + 78, 0, 8);
	pkt[78] = 14;                            /* unknown, length 0 */
	feed(pkt, 94);
	if (db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: NA with a zero-length option was "
		    "processed\n");
		exit(1);
	}

	/* a valid Target LLA option followed by a second one, too long */
	memset(pkt, 0, sizeof(pkt));
	build_na(pkt, tgt, mac);
	pkt[19] = 48;
	pkt[86] = 2; pkt[87] = 2;
	memcpy(pkt + 88, dup, 6);
	feed(pkt, 102);
	if (!db_known(AF_INET6, tgt, mac, "test0")) {
		fprintf(stderr, "FAIL: second Target LLA option was not "
		    "ignored\n");
		exit(1);
	}

	/* an RA with a prefix option, then an option of length 0: no
	 * prefix is learned from it */
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	pkt[6] = 0x02; pkt[11] = 0x4d;
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60; pkt[19] = 56; pkt[20] = 58; pkt[21] = 255;
	pkt[22] = 0xfe; pkt[23] = 0x80; pkt[37] = 0x4d;
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 134; pkt[58] = 64; pkt[60] = 0x07; pkt[61] = 0x08;
	pkt[70] = 3; pkt[71] = 4; pkt[72] = 64; pkt[73] = 0x80;
	pkt[76] = 0x0e; pkt[77] = 0x10;          /* valid lifetime 3600 */
	pkt[86] = 0x20; pkt[87] = 0x01; pkt[88] = 0x0d; pkt[89] = 0xb8;
	pkt[90] = 0x4d;                          /* 2001:db8:4d00::/64 */
	pkt[102] = 14;                           /* unknown, length 0 */
	before = ra_learned_calls;
	feed(pkt, 110);
	if (ra_learned_calls != before) {
		fprintf(stderr, "FAIL: prefix learned from an RA with a "
		    "zero-length option\n");
		exit(1);
	}
}

/* Redirect from src to ff02::1 for dest through target, with a Target
 * LLA option set to mac unless it is NULL; returns the frame length */
static size_t
build_redirect(uint8_t *pkt, const char *src, const char *target,
    const char *dest, const uint8_t *mac)
{
	size_t plen = mac ? 48 : 40;

	memset(pkt, 0, 102);
	pkt[0] = 0x33; pkt[1] = 0x33; pkt[5] = 0x01;
	pkt[6] = 0x02; pkt[11] = 0x01;           /* the router */
	pkt[12] = 0x86; pkt[13] = 0xdd;
	pkt[14] = 0x60; pkt[19] = (uint8_t)plen; pkt[20] = 58; pkt[21] = 255;
	inet_pton(AF_INET6, src, pkt + 22);
	pkt[38] = 0xff; pkt[39] = 0x02; pkt[53] = 0x01;
	pkt[54] = 137;                           /* Redirect */
	inet_pton(AF_INET6, target, pkt + 62);
	inet_pton(AF_INET6, dest, pkt + 78);
	if (mac) {
		pkt[94] = 2; pkt[95] = 1;
		memcpy(pkt + 96, mac, 6);
	}
	return 54 + plen;
}

/* a Redirect makes hosts store its Target LLA for the target, so it is
 * recorded like an NA; one that hosts reject is not */
static void
test_nd_redirect(void)
{
	uint8_t pkt[102], tgt[16], onlink[16];
	uint8_t real[6] = { 0x02, 0, 0, 0, 0, 0x07 };
	uint8_t evil[6] = { 0x02, 0, 0, 0, 0, 0x66 };
	uint8_t rtr[6] = { 0x02, 0, 0, 0, 0, 0x01 };
	int saved_quiet = cfg.quiet, before;
	size_t len;

	cfg.quiet = 0;
	inet_pton(AF_INET6, "fe80::7", tgt);
	feed_na_on("test0", real, "fe80::7");

	/* a forged Redirect pointing traffic for 2001:db8:ff::1 at fe80::7,
	 * which it says is at another MAC */
	before = notify_changed_calls;
	len = build_redirect(pkt, "fe80::1", "fe80::7", "2001:db8:ff::1",
	    evil);
	feed(pkt, len);
	if (notify_changed_calls != before + 1 ||
	    !db_known(AF_INET6, tgt, evil, "test0")) {
		fprintf(stderr, "FAIL: Redirect changing fe80::7 was not "
		    "reported\n");
		exit(1);
	}

	/* without a Target LLA there is no MAC to record, and the Ethernet
	 * source is the router's */
	inet_pton(AF_INET6, "fe80::8", tgt);
	len = build_redirect(pkt, "fe80::1", "fe80::8", "2001:db8:ff::1",
	    NULL);
	feed(pkt, len);
	if (db_known(AF_INET6, tgt, rtr, "test0")) {
		fprintf(stderr, "FAIL: Redirect without Target LLA recorded "
		    "the router's MAC\n");
		exit(1);
	}

	/* a redirect to the on-link destination itself */
	inet_pton(AF_INET6, "2001:db8:ff::9", onlink);
	len = build_redirect(pkt, "fe80::1", "2001:db8:ff::9",
	    "2001:db8:ff::9", evil);
	feed(pkt, len);
	if (!db_known(AF_INET6, onlink, evil, "test0")) {
		fprintf(stderr, "FAIL: on-link Redirect was not recorded\n");
		exit(1);
	}

	/* rejected by hosts: a global target that is not the destination,
	 * a source that is not link-local, a multicast destination */
	inet_pton(AF_INET6, "2001:db8:ff::a", tgt);
	len = build_redirect(pkt, "fe80::1", "2001:db8:ff::a",
	    "2001:db8:ff::1", evil);
	feed(pkt, len);
	len = build_redirect(pkt, "2001:db8::1", "2001:db8:ff::a",
	    "2001:db8:ff::a", evil);
	feed(pkt, len);
	if (db_known(AF_INET6, tgt, evil, "test0")) {
		fprintf(stderr, "FAIL: invalid Redirect was recorded\n");
		exit(1);
	}
	inet_pton(AF_INET6, "fe80::a", tgt);
	len = build_redirect(pkt, "fe80::1", "fe80::a", "ff02::2", evil);
	feed(pkt, len);
	if (db_known(AF_INET6, tgt, evil, "test0")) {
		fprintf(stderr, "FAIL: Redirect for a multicast destination "
		    "was recorded\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* hosts only process ARP requests and replies: another opcode must not
 * change an entry */
static void
test_arp_opcode(void)
{
	uint8_t pkt[42];
	uint8_t spa[4] = { 10, 48, 0, 1 };
	uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x48 };

	for (int op = 0; op <= 9; op++) {
		memset(pkt, 0, sizeof(pkt));
		memset(pkt, 0xff, 6);
		memcpy(pkt + 6, mac, 6);
		pkt[12] = 0x08; pkt[13] = 0x06;
		pkt[15] = 0x01; pkt[16] = 0x08; pkt[18] = 6; pkt[19] = 4;
		pkt[21] = (uint8_t)op;
		memcpy(pkt + 22, mac, 6);
		spa[3] = (uint8_t)(1 + op);
		memcpy(pkt + 28, spa, 4);
		feed(pkt, sizeof(pkt));
		if (db_known(AF_INET, spa, mac, "test0") !=
		    (op == 1 || op == 2)) {
			fprintf(stderr, "FAIL: ARP opcode %d %s\n", op,
			    (op == 1 || op == 2) ? "was dropped" :
			    "was processed");
			exit(1);
		}
	}
}

/* ARP in an 802.1Q priority tag (VLAN ID 0) is processed, other VLAN
 * IDs are not */
static void
test_vlan0_priority_tag(void)
{
	uint8_t pkt[46];
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;
	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[6] = 0x02; pkt[11] = 0x45;
	pkt[12] = 0x81; pkt[13] = 0x00;          /* 802.1Q */
	pkt[14] = 0xa0; pkt[15] = 0x00;          /* priority 5, VLAN ID 0 */
	pkt[16] = 0x08; pkt[17] = 0x06;
	pkt[19] = 0x01; pkt[20] = 0x08; pkt[22] = 6; pkt[23] = 4;
	pkt[25] = 0x02;
	pkt[26] = 0x02; pkt[31] = 0x45;          /* sender MAC */
	pkt[32] = 10; pkt[33] = 45; pkt[34] = 0; pkt[35] = 1;

	before = notify_new_calls;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: priority-tagged ARP was ignored\n");
		exit(1);
	}
	pkt[15] = 0x05;                          /* VLAN ID 5 */
	pkt[35] = 2;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: ARP tagged with VLAN 5 was processed\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

/* ARP behind an 802.1ad priority tag, or behind three stacked priority
 * tags, is processed like Linux does; a VLAN ID under a priority tag
 * is not */
static void
test_stacked_priority_tags(void)
{
	uint8_t pkt[54];
	int saved_quiet = cfg.quiet;
	int before;

	cfg.quiet = 0;
	memset(pkt, 0, sizeof(pkt));
	memset(pkt, 0xff, 6);
	pkt[6] = 0x02; pkt[11] = 0x47;
	pkt[12] = 0x88; pkt[13] = 0xa8;          /* 802.1ad, VLAN ID 0 */
	pkt[16] = 0x81; pkt[17] = 0x00;          /* 802.1Q, VLAN ID 0 */
	pkt[20] = 0x81; pkt[21] = 0x00;          /* 802.1Q, VLAN ID 0 */
	pkt[24] = 0x08; pkt[25] = 0x06;
	pkt[27] = 0x01; pkt[28] = 0x08; pkt[30] = 6; pkt[31] = 4;
	pkt[33] = 0x02;
	pkt[34] = 0x02; pkt[39] = 0x47;          /* sender MAC */
	pkt[40] = 10; pkt[41] = 47; pkt[42] = 0; pkt[43] = 1;

	before = notify_new_calls;
	feed(pkt, sizeof(pkt));
	if (notify_new_calls != before + 1) {
		fprintf(stderr, "FAIL: ARP behind stacked priority tags was "
		    "ignored\n");
		exit(1);
	}

	/* the same ARP behind one 802.1ad priority tag */
	memmove(pkt + 16, pkt + 24, 30);
	pkt[35] = 2;
	feed(pkt, 46);
	if (notify_new_calls != before + 2) {
		fprintf(stderr, "FAIL: ARP behind an 802.1ad priority tag "
		    "was ignored\n");
		exit(1);
	}

	/* VLAN 5 inside a priority tag belongs to a subinterface */
	memmove(pkt + 20, pkt + 16, 30);
	pkt[16] = 0x81; pkt[17] = 0x00; pkt[18] = 0x00; pkt[19] = 0x05;
	pkt[39] = 3;
	feed(pkt, 50);
	if (notify_new_calls != before + 2) {
		fprintf(stderr, "FAIL: VLAN 5 under a priority tag was "
		    "processed\n");
		exit(1);
	}
	cfg.quiet = saved_quiet;
}

static void
test_truncated(void)
{
	uint8_t pkt[4] = { 0x08, 0x06, 0x00, 0x01 };

	feed(pkt, sizeof(pkt));   /* too short for ether_header */
	feed(pkt, 0);             /* empty */
}

static void
test_multiple_then_cleanup(void)
{
	test_arp_request();
	test_arp_reply();
	test_ndp_na();
	test_ndp_na_no_tlla();
	test_ndp_ns();
	test_ndp_ra();
	test_ndp_ra_no_l_flag();
	test_ndp_ra_zero_lifetime();
	test_ndp_ra_withdraw_no_l_flag();
	test_ndp_hlim();
	test_truncated();
}

int
main(void)
{
	cfg.quiet = 1;
	cfg.probe = 0;
	db_init();

	test_arp_request();
	test_arp_reply();
	test_ndp_na();
	test_ndp_na_no_tlla();
	test_ndp_ns();
	test_ndp_ra();
	test_ndp_ra_no_l_flag();
	test_ndp_ra_zero_lifetime();
	test_ndp_ra_bad_lifetimes();
	test_ndp_ra_withdraw_no_l_flag();
	test_ndp_hlim();
	test_three_mac_storm();
	test_storm_per_iface();
	test_temp_takeover();
	test_linklocal_two_links();
	test_storm_alert_dropped();
	test_temp_rotation_probes();
	test_known_not_bogon();
	test_snap_truncated();
	test_jumbo_frame();
	test_arp_hwtype6();
	test_broadcast_mac_claim();
	test_ra_rs_lladdr();
	test_na_ext_header();
	test_na_many_ext_headers();
	test_nd_payload_length();
	test_nd_code_and_checksum();
	test_na_unspecified_source();
	test_nd_bad_options();
	test_nd_redirect();
	test_arp_opcode();
	test_vlan0_priority_tag();
	test_stacked_priority_tags();
	test_truncated();

	/* reset and run batch */
	db_free();
	db_init();
	test_multiple_then_cleanup();

	db_free();
	printf("test_parse: all tests passed\n");
	return 0;
}
