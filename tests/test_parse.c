/*
 * Test harness for parse_packet().
 * Feeds known ARP and NDP packets through the parser, then frees the DB.
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "../neighbot.h"
#include "../db.h"
#include "../parse.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

/* stubs. capture_is_local returns 1 so packets are always processed */
int
capture_is_local(const char *iface, int af, const uint8_t *ip)
{
	(void)iface; (void)af; (void)ip;
	return 1;
}

int
capture_is_own_ip(int af, const uint8_t *ip)
{
	(void)af; (void)ip;
	return 0;
}

void probe_schedule(int af, const uint8_t *ip, const uint8_t *mac,
    int new_af, const uint8_t *new_ip, const char *iface)
{ (void)af; (void)ip; (void)mac; (void)new_af; (void)new_ip; (void)iface; }

void probe_mark_seen(int af, const uint8_t *ip, const uint8_t *mac)
{ (void)af; (void)ip; (void)mac; }

void notify_new(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)iface; }

void notify_changed(int af, const uint8_t *ip, const uint8_t *mac,
    const uint8_t *old_mac, const char *iface, time_t prev_seen)
{ (void)af; (void)ip; (void)mac; (void)old_mac; (void)iface; (void)prev_seen; }

void notify_flipflop(int af, const uint8_t *ip, const uint8_t *mac,
    const uint8_t *old_mac, const char *iface, time_t prev_seen)
{ (void)af; (void)ip; (void)mac; (void)old_mac; (void)iface; (void)prev_seen; }

void notify_bogon(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)iface; }

void notify_reappeared(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface, time_t prev_seen)
{ (void)af; (void)ip; (void)mac; (void)iface; (void)prev_seen; }

void notify_moved(int new_af, const uint8_t *new_ip, const uint8_t *mac,
    int old_af, const uint8_t *old_ip, const char *iface)
{ (void)new_af; (void)new_ip; (void)mac; (void)old_af; (void)old_ip; (void)iface; }

static void
feed(const uint8_t *pkt, size_t len)
{
	struct pcap_pkthdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = len;
	hdr.len    = len;
	parse_packet((u_char *)"test0", &hdr, pkt);
}

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
	test_truncated();

	/* reset and run batch */
	db_free();
	db_init();
	test_multiple_then_cleanup();

	db_free();
	printf("test_parse: all tests passed\n");
	return 0;
}
