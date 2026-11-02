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
#include <sys/stat.h>
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

	capture_add_own_ip("eth0", AF_INET, ip4);
	capture_add_own_ip("eth0", AF_INET6, ip6);

	/* a link-local with a KAME-embedded scope id matches the address
	 * as seen on the wire */
	{
		uint8_t kame[16] = { 0xfe, 0x80, 0x00, 0x03, 0, 0, 0, 0,
		                     0, 0, 0, 0, 0, 0, 0, 0x77 };
		uint8_t wire[16] = { 0xfe, 0x80, 0x00, 0x00, 0, 0, 0, 0,
		                     0, 0, 0, 0, 0, 0, 0, 0x77 };

		capture_add_own_ip("eth0", AF_INET6, kame);
		ASSERT(capture_is_own_ip(AF_INET6, wire) == 1,
		       "scoped link-local should match the wire address");
	}

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
test_probe_src(void)
{
	uint8_t a1[4] = { 192, 168, 1, 10 }, m24[4] = { 255, 255, 255, 0 };
	uint8_t a2[4] = { 10, 0, 0, 10 }, m8[4] = { 255, 0, 0, 0 };
	uint8_t t1[4] = { 10, 9, 9, 9 }, t2[4] = { 172, 16, 0, 1 };
	uint8_t g6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                   0, 0, 0, 0, 0, 0, 0, 0x01 };
	uint8_t ll6[16] = { 0xfe, 0x80, 0, 0x02, 0, 0, 0, 0,
	                    0, 0, 0, 0, 0, 0, 0, 0x01 };
	uint8_t src[16];

	capture_reset_subnets();
	capture_reset_own_ips();

	ASSERT(capture_probe_src("eth0", AF_INET, t1, src) == 0,
	       "no address, IPv4 source should be unspecified");
	ASSERT(src[0] == 0 && src[3] == 0, "unspecified IPv4 source");

	capture_add_subnet("eth0", AF_INET, a1, m24);
	capture_add_subnet("eth0", AF_INET, a2, m8);
	capture_add_subnet("eth1", AF_INET, a1, m24);

	ASSERT(capture_probe_src("eth0", AF_INET, t1, src) == 1 &&
	       memcmp(src, a2, 4) == 0,
	       "IPv4 source should be in the target's subnet");
	ASSERT(capture_probe_src("eth0", AF_INET, t2, src) == 1 &&
	       memcmp(src, a1, 4) == 0,
	       "IPv4 source should fall back to the first address");
	ASSERT(capture_probe_src("eth2", AF_INET, t1, src) == 0,
	       "no IPv4 address on eth2");

	ASSERT(capture_probe_src("eth0", AF_INET6, g6, src) == 0,
	       "no link-local, IPv6 source should be unspecified");
	capture_add_own_ip("eth0", AF_INET6, g6);
	capture_add_own_ip("eth1", AF_INET6, ll6);
	ASSERT(capture_probe_src("eth0", AF_INET6, g6, src) == 0,
	       "a global address is not used as NS source");
	capture_add_own_ip("eth0", AF_INET6, ll6);
	ASSERT(capture_probe_src("eth0", AF_INET6, g6, src) == 1 &&
	       src[0] == 0xfe && src[1] == 0x80 && src[2] == 0 &&
	       src[3] == 0 && src[15] == 0x01,
	       "IPv6 source should be the link-local, scope bytes cleared");

	capture_reset_subnets();
	capture_reset_own_ips();
	/* prefix inside a configured subnet, and broader ones */
	{
		uint8_t net[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0x01, 0, 0,
		                    0, 0, 0, 0, 0, 0, 0, 0x01 };
		uint8_t m64[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		                    0xff, 0xff };
		uint8_t pfx[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0x01 };

		capture_add_subnet("eth0", AF_INET6, net, m64);
		ASSERT(capture_prefix_configured("eth0", AF_INET6, pfx, 64),
		       "the configured /64 should match");
		ASSERT(!capture_prefix_configured("eth0", AF_INET6, pfx, 48),
		       "a broader /48 should not count as configured");
		ASSERT(!capture_prefix_configured("eth1", AF_INET6, pfx, 64),
		       "another interface's subnet should not match");
		capture_reset_subnets();
	}

	printf("  probe_src: ok\n");
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
test_learned_subnet(void)
{
	uint8_t pfx[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                    0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t ip_in[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                      0, 0, 0, 0, 0, 0, 0, 0x01 };
	uint8_t ip_out[16] = { 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0,
	                       0, 0, 0, 0, 0, 0, 0, 0x01 };
	int r;

	capture_reset_subnets();
	capture_reset_learned_subnets();

	/* no subnets at all: safe default is local */
	ASSERT(capture_is_local("eth0", AF_INET6, ip_in) == 1,
	    "safe default before any learn");

	/* first add returns 1 (new), refresh returns 0 */
	r = capture_add_learned_subnet("eth0", AF_INET6, pfx, 64, 3600, 0);
	ASSERT(r == 1, "first add should return 1");
	r = capture_add_learned_subnet("eth0", AF_INET6, pfx, 64, 3600, 0);
	ASSERT(r == 0, "refresh should return 0");

	/* learned prefix: in-prefix is local, out-of-prefix is bogon */
	ASSERT(capture_is_local("eth0", AF_INET6, ip_in) == 1,
	    "learned prefix should match");
	ASSERT(capture_is_local("eth0", AF_INET6, ip_out) == 0,
	    "out-of-prefix should be bogon");
	ASSERT(capture_is_local_any(AF_INET6, ip_in) == 1,
	    "learned prefix should match _any");

	/* wrong iface must NOT match a learned prefix scoped to eth0 */
	ASSERT(capture_is_local("eth1", AF_INET6, ip_in) == 1,
	    "eth1 has no subnets, safe default");

	/* zero lifetime withdraws a matching learned prefix */
	r = capture_add_learned_subnet("eth0", AF_INET6, pfx, 64, 0, 0);
	ASSERT(r == 2, "zero lifetime should withdraw a learned prefix");
	ASSERT(capture_is_local("eth0", AF_INET6, ip_out) == 1,
	    "after withdrawal, no subnets, safe default is local");
	/* withdrawing an unknown prefix has nothing to do */
	r = capture_add_learned_subnet("eth0", AF_INET6, pfx, 64, 0, 0);
	ASSERT(r == -1, "withdrawing an unknown prefix should return -1");

	/* with keep_longer, a short refresh leaves a live prefix as it was */
	r = capture_add_learned_subnet("eth0", AF_INET6, pfx, 64, 3600, 0);
	ASSERT(r == 1, "re-learning a withdrawn prefix should return 1");
	r = capture_add_learned_subnet("eth0", AF_INET6, pfx, 64, 1, 1);
	ASSERT(r == 0, "short refresh should return 0");
	sleep(2);
	ASSERT(capture_is_local("eth0", AF_INET6, ip_out) == 0,
	    "a short refresh with keep_longer cut the prefix short");

	/* prefix_len > 128 is rejected before the lifetime check */
	r = capture_add_learned_subnet("eth0", AF_INET6, pfx, 200, 60, 0);
	ASSERT(r == -1, "prefix_len > 128 should be rejected");

	capture_reset_learned_subnets();
	printf("  learned_subnet: ok\n");
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

/* a /32 or /128 address matches itself but is no subnet: DHCPv6 leases
 * are /128, and a /32 host reaches its gateway through an on-link route */
static int
test_host_mask(void)
{
	uint8_t lease[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                      0, 0, 0, 0, 0, 0, 0x12, 0x34 };
	uint8_t m128[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t peer6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                      0, 0, 0, 0, 0, 0, 0, 0x02 };
	uint8_t host[4] = { 192, 0, 2, 10 };
	uint8_t m32[4] = { 255, 255, 255, 255 };
	uint8_t gw[4] = { 192, 0, 2, 1 };
	uint8_t net[4] = { 10, 0, 0, 5 };
	uint8_t m24[4] = { 255, 255, 255, 0 };
	uint8_t vip[4] = { 198, 51, 100, 7 };
	uint8_t foreign[4] = { 203, 0, 113, 9 };

	capture_reset_subnets();
	capture_reset_learned_subnets();

	/* only a /128 lease: the on-link neighbour is not a bogon */
	capture_add_subnet("eth0", AF_INET6, lease, m128);
	ASSERT(capture_is_local("eth0", AF_INET6, peer6) == 1,
	       "neighbour of a /128 lease should be local");

	/* only a /32 address: the on-link gateway is not a bogon */
	capture_add_subnet("eth0", AF_INET, host, m32);
	ASSERT(capture_is_local("eth0", AF_INET, gw) == 1,
	       "gateway of a /32 host should be local");

	/* a /32 alias next to a /24 still counts as local itself, and the
	 * /24 still makes other addresses foreign */
	capture_reset_subnets();
	capture_add_subnet("eth0", AF_INET, net, m24);
	capture_add_subnet("eth0", AF_INET, vip, m32);
	ASSERT(capture_is_local("eth0", AF_INET, vip) == 1,
	       "a /32 alias should be local");
	ASSERT(capture_is_local("eth0", AF_INET, foreign) == 0,
	       "an address outside the /24 should not be local");

	printf("  host_mask: ok\n");
	return 0;
}

/* an RA prefix of /64 or longer holding a /128 lease of the host is
 * configured, though no subnet contains it; a shorter one is not, nor
 * one that only holds an address with a subnet of its own */
static int
test_prefix_configured(void)
{
	uint8_t lease[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                      0, 0, 0, 0, 0, 0, 0x12, 0x34 };
	uint8_t slaac[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x02,
	                      0, 0, 0, 0, 0, 0, 0x56, 0x78 };
	uint8_t pfx[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	                    0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t other[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x01,
	                      0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t m128[16], m64[16] = { 0xff, 0xff, 0xff, 0xff,
	                              0xff, 0xff, 0xff, 0xff };

	/* as getifaddrs() reports a lease: a /128 subnet and the address */
	memset(m128, 0xff, sizeof(m128));
	capture_reset_subnets();
	capture_reset_own_ips();
	capture_add_subnet("eth0", AF_INET6, lease, m128);
	capture_add_own_ip("eth0", AF_INET6, lease);

	ASSERT(capture_prefix_configured("eth0", AF_INET6, pfx, 64) == 1,
	       "the /64 holding the lease should count as configured");
	ASSERT(capture_prefix_configured("eth0", AF_INET6, pfx, 48) == 0,
	       "a /48 holding the lease should not count as configured");
	ASSERT(capture_prefix_configured("eth0", AF_INET6, other, 64) == 0,
	       "another prefix should not count as configured");
	ASSERT(capture_prefix_configured("eth1", AF_INET6, pfx, 64) == 0,
	       "the lease of eth0 should not count on eth1");

	/* a SLAAC address in 2001:db8:0:2::/64 */
	capture_reset_subnets();
	capture_reset_own_ips();
	capture_add_subnet("eth0", AF_INET6, slaac, m64);
	capture_add_own_ip("eth0", AF_INET6, slaac);
	ASSERT(capture_prefix_configured("eth0", AF_INET6, slaac, 64) == 1,
	       "the /64 of the address should count as configured");
	ASSERT(capture_prefix_configured("eth0", AF_INET6, pfx, 48) == 0,
	       "a /48 around a configured /64 should not count as "
	       "configured");

	capture_reset_subnets();
	capture_reset_own_ips();
	printf("  prefix_configured: ok\n");
	return 0;
}

/* the broadcast address of a subnet of the interface, and only that;
 * a /31 or a /32 has none */
static int
test_bcast(void)
{
	uint8_t a24[4] = { 192, 0, 2, 1 }, m24[4] = { 255, 255, 255, 0 };
	uint8_t a16[4] = { 172, 16, 0, 1 }, m16[4] = { 255, 255, 0, 0 };
	uint8_t a31[4] = { 10, 0, 0, 0 }, m31[4] = { 255, 255, 255, 254 };
	uint8_t a32[4] = { 10, 1, 0, 5 }, m32[4] = { 255, 255, 255, 255 };
	uint8_t b24[4] = { 192, 0, 2, 255 }, b16[4] = { 172, 16, 255, 255 };
	uint8_t n24[4] = { 192, 0, 2, 0 }, h24[4] = { 192, 0, 2, 254 };
	uint8_t l16[4] = { 172, 16, 0, 255 }, b31[4] = { 10, 0, 0, 1 };

	capture_reset_subnets();
	capture_add_subnet("eth0", AF_INET, a24, m24);
	capture_add_subnet("eth0", AF_INET, a16, m16);
	capture_add_subnet("eth0", AF_INET, a31, m31);
	capture_add_subnet("eth0", AF_INET, a32, m32);

	ASSERT(capture_is_bcast("eth0", b24) == 1,
	       "192.0.2.255 should be the broadcast address of the /24");
	ASSERT(capture_is_bcast("eth0", b16) == 1,
	       "172.16.255.255 should be the broadcast address of the /16");
	ASSERT(capture_is_bcast("eth0", n24) == 0,
	       "the network address is not a broadcast address");
	ASSERT(capture_is_bcast("eth0", h24) == 0,
	       "192.0.2.254 is not a broadcast address");
	ASSERT(capture_is_bcast("eth0", l16) == 0,
	       "172.16.0.255 is not a broadcast address of the /16");
	ASSERT(capture_is_bcast("eth0", b31) == 0,
	       "a /31 has no broadcast address");
	ASSERT(capture_is_bcast("eth0", a32) == 0,
	       "a /32 has no broadcast address");
	ASSERT(capture_is_bcast("eth1", b24) == 0,
	       "a subnet of eth0 says nothing about eth1");

	capture_reset_subnets();
	printf("  bcast: ok\n");
	return 0;
}

#if defined(__linux__)

#define VLAN_TMP "tmp/test_vlan_parents.tmp"

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
	mkdir("tmp", 0755);

	printf("test_capture:\n");
	rc |= test_linklocal();
	rc |= test_ipv4_subnet();
	rc |= test_no_subnet_for_af();
	rc |= test_ipv6_subnet();
	rc |= test_own_ip();
	rc |= test_probe_src();
	rc |= test_is_local_any();
	rc |= test_learned_subnet();
	rc |= test_host_mask();
	rc |= test_prefix_configured();
	rc |= test_bcast();

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
