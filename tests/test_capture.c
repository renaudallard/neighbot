/*
 * Test harness for capture_is_local().
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
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

	if (rc == 0)
		printf("test_capture: all tests passed\n");
	return rc;
}
