/*
 * Fuzz target for parse_packet().
 * Feeds raw Ethernet frames into the ARP/NDP parser.
 *
 * Build: make fuzz_parse (from project root)
 * Run:   ./fuzz_parse [-max_total_time=60]
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
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

	parse_packet((u_char *)"fuzz0", &hdr, data);

	/* reset DB so entries do not accumulate across iterations */
	db_free();
	db_init();
	return 0;
}
