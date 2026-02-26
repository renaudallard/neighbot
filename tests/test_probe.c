/*
 * Test harness for probe.c packet builders and state machine.
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

#include "../neighbot.h"
#include "../db.h"
#include "../parse.h"
#include "../probe.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

/* stubs */
int
capture_is_local(const char *iface, int af, const uint8_t *ip)
{
	(void)iface; (void)af; (void)ip;
	return 1;
}

void handle_moved(int new_af, const uint8_t *new_ip, const uint8_t *mac,
    int old_af, const uint8_t *old_ip, const char *iface)
{ (void)new_af; (void)new_ip; (void)mac; (void)old_af; (void)old_ip; (void)iface; }

void handle_multiple_ips(int af, const uint8_t *ip, const uint8_t *mac,
    int other_af, const uint8_t *other_ip, const char *iface)
{ (void)af; (void)ip; (void)mac; (void)other_af; (void)other_ip; (void)iface; }

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

#define ASSERT(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
		return 1; \
	} \
} while (0)

static int
test_build_arp_request(void)
{
	uint8_t buf[128];
	uint8_t src_mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	uint8_t target_ip[4] = { 192, 168, 1, 1 };
	int len;

	/* too small buffer */
	len = build_arp_request(buf, 10, src_mac, target_ip);
	ASSERT(len == -1, "build_arp_request should fail on small buffer");

	len = build_arp_request(buf, sizeof(buf), src_mac, target_ip);
	ASSERT(len == 42, "build_arp_request should return 42 bytes");

	/* Ethernet dst = broadcast */
	ASSERT(buf[0] == 0xff && buf[1] == 0xff && buf[2] == 0xff &&
	       buf[3] == 0xff && buf[4] == 0xff && buf[5] == 0xff,
	       "ARP dst should be broadcast");

	/* Ethernet src = local MAC */
	ASSERT(memcmp(buf + 6, src_mac, 6) == 0,
	       "ARP src should be local MAC");

	/* Ethertype = 0x0806 (ARP) */
	ASSERT(buf[12] == 0x08 && buf[13] == 0x06,
	       "ARP ethertype should be 0x0806");

	/* htype=1 */
	ASSERT(buf[14] == 0x00 && buf[15] == 0x01, "htype should be 1");
	/* ptype=0x0800 */
	ASSERT(buf[16] == 0x08 && buf[17] == 0x00, "ptype should be 0x0800");
	/* hlen=6 */
	ASSERT(buf[18] == 6, "hlen should be 6");
	/* plen=4 */
	ASSERT(buf[19] == 4, "plen should be 4");
	/* oper=1 (request) */
	ASSERT(buf[20] == 0x00 && buf[21] == 0x01, "oper should be 1");

	/* sender hardware address = local MAC */
	ASSERT(memcmp(buf + 22, src_mac, 6) == 0, "sha should be local MAC");

	/* sender protocol address = 0.0.0.0 */
	ASSERT(buf[28] == 0 && buf[29] == 0 && buf[30] == 0 && buf[31] == 0,
	       "spa should be 0.0.0.0");

	/* target protocol address = 192.168.1.1 */
	ASSERT(memcmp(buf + 38, target_ip, 4) == 0,
	       "tpa should be target IP");

	printf("  build_arp_request: ok\n");
	return 0;
}

static int
test_icmp6_checksum(void)
{
	/* Known NDP NS: src=::, dst=ff02::1:ff00:1, ICMPv6 NS for 2001:db8::1 */
	uint8_t src6[16] = { 0 };
	uint8_t dst6[16] = {
		0xff, 0x02, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0x01, 0xff, 0x00, 0x00, 0x01
	};
	/* ICMPv6 NS: type=135, code=0, cksum=0, reserved=0, target=2001:db8::1 */
	uint8_t icmp[24] = { 0 };
	icmp[0] = 135;
	icmp[8] = 0x20; icmp[9] = 0x01; icmp[10] = 0x0d; icmp[11] = 0xb8;
	icmp[23] = 0x01;

	uint16_t cksum = icmp6_checksum(src6, dst6, icmp, 24);

	/* verify it is nonzero (valid checksum) */
	ASSERT(cksum != 0, "ICMPv6 checksum should be nonzero");

	/* verify: re-insert checksum and recompute. should get 0 */
	icmp[2] = (uint8_t)(cksum >> 8);
	icmp[3] = (uint8_t)(cksum & 0xff);
	uint16_t verify = icmp6_checksum(src6, dst6, icmp, 24);
	ASSERT(verify == 0, "ICMPv6 checksum verification should yield 0");

	printf("  icmp6_checksum: ok\n");
	return 0;
}

static int
test_build_ndp_ns(void)
{
	uint8_t buf[128];
	uint8_t src_mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	uint8_t target_ip6[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01
	};
	int len;

	/* too small buffer */
	len = build_ndp_ns(buf, 10, src_mac, target_ip6);
	ASSERT(len == -1, "build_ndp_ns should fail on small buffer");

	len = build_ndp_ns(buf, sizeof(buf), src_mac, target_ip6);
	ASSERT(len == 78, "build_ndp_ns should return 78 bytes");

	/* Ethernet dst = solicited-node multicast MAC: 33:33:ff:00:00:01 */
	ASSERT(buf[0] == 0x33 && buf[1] == 0x33 && buf[2] == 0xff,
	       "NDP dst should start with 33:33:ff");
	ASSERT(buf[3] == target_ip6[13] && buf[4] == target_ip6[14] &&
	       buf[5] == target_ip6[15],
	       "NDP dst last 3 bytes should match target");

	/* Ethernet src = local MAC */
	ASSERT(memcmp(buf + 6, src_mac, 6) == 0,
	       "NDP src should be local MAC");

	/* Ethertype = 0x86dd (IPv6) */
	ASSERT(buf[12] == 0x86 && buf[13] == 0xdd,
	       "NDP ethertype should be 0x86dd");

	/* IPv6 version = 6 */
	ASSERT((buf[14] >> 4) == 6, "IPv6 version should be 6");

	/* payload length = 24 */
	ASSERT(buf[18] == 0x00 && buf[19] == 24,
	       "IPv6 payload length should be 24");

	/* next header = ICMPv6 (58) */
	ASSERT(buf[20] == 58, "next header should be ICMPv6");

	/* hop limit = 255 */
	ASSERT(buf[21] == 255, "hop limit should be 255");

	/* ICMPv6 NS type = 135 */
	ASSERT(buf[54] == 135, "ICMPv6 type should be 135 (NS)");

	/* target address */
	ASSERT(memcmp(buf + 62, target_ip6, 16) == 0,
	       "NS target should be target IP");

	/* verify checksum: extract and re-verify */
	uint8_t src_ip6[16] = { 0 };   /* :: */
	uint8_t sol_mc[16] = { 0 };
	sol_mc[0] = 0xff; sol_mc[1] = 0x02;
	sol_mc[11] = 0x01; sol_mc[12] = 0xff;
	sol_mc[13] = target_ip6[13];
	sol_mc[14] = target_ip6[14];
	sol_mc[15] = target_ip6[15];

	uint16_t verify = icmp6_checksum(src_ip6, sol_mc, buf + 54, 24);
	ASSERT(verify == 0, "NDP NS checksum should verify to 0");

	printf("  build_ndp_ns: ok\n");
	return 0;
}

static int
test_probe_schedule(void)
{
	uint8_t ip[4] = { 192, 168, 1, 1 };
	uint8_t mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	uint8_t new_ip[4] = { 192, 168, 1, 2 };

	probe_reset();

	/* schedule one probe */
	probe_schedule(AF_INET, ip, mac, AF_INET, new_ip, "eth0");

	/* duplicate should be silently ignored (no crash, no second slot) */
	probe_schedule(AF_INET, ip, mac, AF_INET, new_ip, "eth0");

	/* fill all remaining slots */
	for (int i = 1; i < PROBE_MAX_SLOTS; i++) {
		uint8_t ip2[4] = { 10, 0, 0, (uint8_t)i };
		probe_schedule(AF_INET, ip2, mac, AF_INET, new_ip, "eth0");
	}

	/* 33rd should fail (logged as "no free slots") but not crash */
	{
		uint8_t ip3[4] = { 10, 1, 0, 1 };
		probe_schedule(AF_INET, ip3, mac, AF_INET, new_ip, "eth0");
	}

	probe_reset();
	printf("  probe_schedule: ok\n");
	return 0;
}

static int
test_probe_mark_seen(void)
{
	uint8_t ip[4] = { 192, 168, 1, 1 };
	uint8_t mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	uint8_t new_ip[4] = { 192, 168, 1, 2 };
	uint8_t other_mac[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	probe_reset();

	/* schedule and mark as answered (same MAC) */
	probe_schedule(AF_INET, ip, mac, AF_INET, new_ip, "eth0");
	probe_mark_seen(AF_INET, ip, mac);

	/* schedule another and mark as stolen (different MAC) */
	uint8_t ip2[4] = { 10, 0, 0, 1 };
	probe_schedule(AF_INET, ip2, mac, AF_INET, new_ip, "eth0");
	probe_mark_seen(AF_INET, ip2, other_mac);

	probe_reset();
	printf("  probe_mark_seen: ok\n");
	return 0;
}

int
main(void)
{
	int rc = 0;

	cfg.quiet = 1;
	cfg.probe = 1;
	db_init();

	printf("test_probe:\n");
	rc |= test_build_arp_request();
	rc |= test_icmp6_checksum();
	rc |= test_build_ndp_ns();
	rc |= test_probe_schedule();
	rc |= test_probe_mark_seen();

	db_free();

	if (rc == 0)
		printf("test_probe: all tests passed\n");
	return rc;
}
