/*
 * Fuzz target for parse_packet().
 * Feeds raw Ethernet frames into the ARP/NDP parser.
 *
 * Build: make fuzz_parse (from project root)
 * Run:   ./fuzz_parse -close_fd_mask=2 [-max_total_time=60]
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>

#include "../neighbot.h"
#include "../db.h"
#include "../parse.h"
#include "../tests/nd_cksum.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

/* stubs. capture_is_local_fresh returns 1 so packets are always processed */
int
capture_is_local_fresh(const char *iface, int af, const uint8_t *ip)
{
	(void)iface; (void)af; (void)ip;
	return 1;
}

int
capture_is_local_any(int af, const uint8_t *ip)
{
	(void)af; (void)ip;
	return 1;
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

int
capture_is_bcast(const char *iface, const uint8_t *ip)
{
	(void)iface; (void)ip;
	return 0;
}

int
capture_add_learned_subnet(const char *iface, int af,
    const uint8_t *addr, int prefix_len, uint32_t lifetime_sec,
    int keep_longer)
{
	(void)iface; (void)af; (void)addr; (void)prefix_len; (void)lifetime_sec;
	(void)keep_longer;
	return 0;
}

void probe_schedule(int af, const uint8_t *ip, const uint8_t *mac,
    int new_af, const uint8_t *new_ip, const char *new_iface,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)new_af; (void)new_ip;
  (void)new_iface; (void)iface; }

void probe_mark_seen(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface)
{ (void)af; (void)ip; (void)mac; (void)iface; }

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

void notify_fragment(const uint8_t *src, const uint8_t *dst,
    const uint8_t *mac, const char *iface, int type, const uint8_t *target)
{ (void)src; (void)dst; (void)mac; (void)iface; (void)type; (void)target; }

void notify_reappeared(int af, const uint8_t *ip, const uint8_t *mac,
    const char *iface, time_t prev_seen)
{ (void)af; (void)ip; (void)mac; (void)iface; (void)prev_seen; }

void notify_moved(int new_af, const uint8_t *new_ip, const char *new_iface,
    const uint8_t *mac, int old_af, const uint8_t *old_ip,
    const char *old_iface)
{ (void)new_af; (void)new_ip; (void)new_iface; (void)mac; (void)old_af;
  (void)old_ip; (void)old_iface; }

int notify_storm(int af, const uint8_t *ip, const uint8_t *mac_a,
    const uint8_t *mac_b, const char *iface)
{ (void)af; (void)ip; (void)mac_a; (void)mac_b; (void)iface; return 1; }

void notify_ra_learned(const char *iface, const uint8_t *prefix,
    int prefix_len, const uint8_t *router, uint32_t lifetime)
{ (void)iface; (void)prefix; (void)prefix_len; (void)router; (void)lifetime; }

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int init;

	if (!init) {
		cfg.quiet = 1;
		cfg.probe = 0;
		db_init();
		init = 1;
	}

	struct pcap_pkthdr hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = size;
	hdr.len    = size;

	/* give ND messages a valid checksum, or almost none would get past
	 * the check to the code behind it; frames longer than the snap
	 * length are rejected by the parser, so pass them as they are */
	static uint8_t buf[SNAP_LEN];

	if (size <= sizeof(buf)) {
		memcpy(buf, data, size);
		nd_fix_cksum(buf, size);
		data = buf;
	}
	parse_packet((u_char *)"fuzz0", &hdr, data);

	/* reset DB so entries do not accumulate across iterations */
	db_free();
	db_init();
	return 0;
}
