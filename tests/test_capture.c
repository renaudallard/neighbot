/*
 * Test harness for capture_is_local().
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../neighbot.h"
#include "../capture.h"
#include "../db.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

#define ASSERT(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
		return 1; \
	} \
} while (0)

static int
test_linklocal(void)
{
	uint8_t ll4[4] = { 169, 254, 1, 1 };
	uint8_t ll6[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
	                     0, 0, 0, 0, 0, 0, 0, 0x01 };

	capture_reset_subnets();

	/* link-local IPv4 is always local, no subnets needed */
	ASSERT(capture_is_local("eth0", AF_INET, ll4) == 1,
	       "169.254.1.1 should be local");

	/* link-local IPv6 is always local, no subnets needed */
	ASSERT(capture_is_local("eth0", AF_INET6, ll6) == 1,
	       "fe80::1 should be local");

	printf("  linklocal: ok\n");
	return 0;
}

static int
test_ipv4_subnet(void)
{
	uint8_t addr[4] = { 192, 168, 1, 0 };
	uint8_t mask[4] = { 255, 255, 255, 0 };
	uint8_t ip_in[4] = { 192, 168, 1, 100 };
	uint8_t ip_out[4] = { 10, 0, 0, 1 };

	capture_reset_subnets();
	capture_add_subnet("eth0", AF_INET, addr, mask);

	/* in subnet, correct iface */
	ASSERT(capture_is_local("eth0", AF_INET, ip_in) == 1,
	       "192.168.1.100 on eth0 should be local");

	/* not in subnet */
	ASSERT(capture_is_local("eth0", AF_INET, ip_out) == 0,
	       "10.0.0.1 on eth0 should not be local");

	/* correct IP, wrong iface. no subnets for eth1, returns 1 (safe default) */
	ASSERT(capture_is_local("eth1", AF_INET, ip_in) == 1,
	       "192.168.1.100 on eth1 should be local (no subnets for eth1)");

	printf("  ipv4_subnet: ok\n");
	return 0;
}

static int
test_no_subnet_for_af(void)
{
	uint8_t ip6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                     0, 0, 0, 0, 0, 0, 0, 0x01 };

	capture_reset_subnets();

	/* no subnets at all. should return 1 (cannot determine) */
	ASSERT(capture_is_local("eth0", AF_INET6, ip6) == 1,
	       "no IPv6 subnets should return local (cannot determine)");

	printf("  no_subnet_for_af: ok\n");
	return 0;
}

static int
test_own_ip(void)
{
	uint8_t ip4[4] = { 192, 168, 1, 1 };
	uint8_t ip4_other[4] = { 10, 0, 0, 1 };
	uint8_t ip6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                     0, 0, 0, 0, 0, 0, 0, 0x01 };
	uint8_t ip6_other[16] = { 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0,
	                           0, 0, 0, 0, 0, 0, 0, 0x01 };

	capture_reset_own_ips();

	/* no own IPs configured. should return 0 */
	ASSERT(capture_is_own_ip(AF_INET, ip4) == 0,
	       "no own IPs, should not match");

	capture_add_own_ip(AF_INET, ip4);
	capture_add_own_ip(AF_INET6, ip6);

	ASSERT(capture_is_own_ip(AF_INET, ip4) == 1,
	       "192.168.1.1 should be own IP");
	ASSERT(capture_is_own_ip(AF_INET, ip4_other) == 0,
	       "10.0.0.1 should not be own IP");
	ASSERT(capture_is_own_ip(AF_INET6, ip6) == 1,
	       "2001:db8::1 should be own IP");
	ASSERT(capture_is_own_ip(AF_INET6, ip6_other) == 0,
	       "2001:db9::1 should not be own IP");

	/* reset clears all */
	capture_reset_own_ips();
	ASSERT(capture_is_own_ip(AF_INET, ip4) == 0,
	       "after reset, should not match");

	printf("  own_ip: ok\n");
	return 0;
}

static int
test_ipv6_subnet(void)
{
	/* 2001:db8::/32 */
	uint8_t addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                      0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t mask[16] = { 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
	                      0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t ip_in[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                       0, 0, 0, 0, 0, 0, 0, 0x01 };
	uint8_t ip_out[16] = { 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0,
	                        0, 0, 0, 0, 0, 0, 0, 0x01 };

	capture_reset_subnets();
	capture_add_subnet("eth0", AF_INET6, addr, mask);

	ASSERT(capture_is_local("eth0", AF_INET6, ip_in) == 1,
	       "2001:db8::1 on eth0 should be local");

	ASSERT(capture_is_local("eth0", AF_INET6, ip_out) == 0,
	       "2001:db9::1 on eth0 should not be local");

	printf("  ipv6_subnet: ok\n");
	return 0;
}

static int
test_is_local_any(void)
{
	uint8_t addr1[4] = { 192, 168, 1, 0 };
	uint8_t mask1[4] = { 255, 255, 255, 0 };
	uint8_t addr2[4] = { 172, 20, 0, 0 };
	uint8_t mask2[4] = { 255, 255, 0, 0 };

	uint8_t ip_eth0[4] = { 192, 168, 1, 100 };
	uint8_t ip_eth1[4] = { 172, 20, 0, 240 };
	uint8_t ip_bogon[4] = { 10, 0, 0, 1 };

	capture_reset_subnets();
	capture_add_subnet("eth0", AF_INET, addr1, mask1);
	capture_add_subnet("eth1", AF_INET, addr2, mask2);

	/* 172.20.0.240 is not local to eth0 but is local to any */
	ASSERT(capture_is_local("eth0", AF_INET, ip_eth1) == 0,
	       "172.20.0.240 should not be local to eth0");
	ASSERT(capture_is_local_any(AF_INET, ip_eth1) == 1,
	       "172.20.0.240 should be local to some interface");

	/* 192.168.1.100 is local to eth0 and local to any */
	ASSERT(capture_is_local("eth0", AF_INET, ip_eth0) == 1,
	       "192.168.1.100 should be local to eth0");
	ASSERT(capture_is_local_any(AF_INET, ip_eth0) == 1,
	       "192.168.1.100 should be local to some interface");

	/* 10.0.0.1 is not local to any */
	ASSERT(capture_is_local_any(AF_INET, ip_bogon) == 0,
	       "10.0.0.1 should not be local to any interface");

	printf("  is_local_any: ok\n");
	return 0;
}

#if defined(__linux__)

#define VLAN_TMP "/tmp/test_vlan_parents.tmp"

static void
write_file(const char *path, const char *data)
{
	FILE *fp = fopen(path, "w");

	if (!fp) {
		perror(path);
		exit(1);
	}
	fputs(data, fp);
	fclose(fp);
}

static int
test_vlan_parents_basic(void)
{
	char parents[64][32];
	int n;

	write_file(VLAN_TMP,
	    "VLAN Dev name    | VLAN ID\n"
	    "Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n"
	    "eth0.100       | 100  | eth0\n"
	    "eth0.200       | 200  | eth0\n");

	n = capture_parse_vlan_parents(VLAN_TMP, parents, 64);
	unlink(VLAN_TMP);

	ASSERT(n == 1, "should find 1 unique parent");
	ASSERT(strcmp(parents[0], "eth0") == 0,
	       "parent should be eth0");

	printf("  vlan_parents_basic: ok\n");
	return 0;
}

static int
test_vlan_parents_multi(void)
{
	char parents[64][32];
	int n;

	write_file(VLAN_TMP,
	    "VLAN Dev name    | VLAN ID\n"
	    "Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n"
	    "eth0.100       | 100  | eth0\n"
	    "eth1.200       | 200  | eth1\n");

	n = capture_parse_vlan_parents(VLAN_TMP, parents, 64);
	unlink(VLAN_TMP);

	ASSERT(n == 2, "should find 2 unique parents");

	printf("  vlan_parents_multi: ok\n");
	return 0;
}

static int
test_vlan_parents_empty(void)
{
	char parents[64][32];
	int n;

	write_file(VLAN_TMP, "");

	n = capture_parse_vlan_parents(VLAN_TMP, parents, 64);
	unlink(VLAN_TMP);

	ASSERT(n == 0, "empty file should return 0");

	printf("  vlan_parents_empty: ok\n");
	return 0;
}

static int
test_vlan_parents_nofile(void)
{
	char parents[64][32];
	int n;

	n = capture_parse_vlan_parents("/nonexistent/path", parents, 64);

	ASSERT(n == 0, "nonexistent path should return 0");

	printf("  vlan_parents_nofile: ok\n");
	return 0;
}

#endif /* __linux__ */

int
main(void)
{
	int rc = 0;

	cfg.quiet = 1;

	printf("test_capture:\n");
	rc |= test_linklocal();
	rc |= test_ipv4_subnet();
	rc |= test_no_subnet_for_af();
	rc |= test_ipv6_subnet();
	rc |= test_own_ip();
	rc |= test_is_local_any();

#if defined(__linux__)
	rc |= test_vlan_parents_basic();
	rc |= test_vlan_parents_multi();
	rc |= test_vlan_parents_empty();
	rc |= test_vlan_parents_nofile();
#endif

	if (rc == 0)
		printf("test_capture: all tests passed\n");
	return rc;
}
