/*
 * Test harness for db_load / db_save / db_free.
 * Exercises the CSV database with known inputs.
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../neighbot.h"
#include "../db.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

#define TEST_TMP  "tmp/test_dbload.tmp"
#define TEST_TMP2 "tmp/test_dbload2.tmp"

/* time() as db.c sees it: the real clock moved by clock_step, to step
 * the wall clock */
static time_t clock_step;

time_t
time(time_t *tp)
{
	struct timespec ts;
	time_t t;

	if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
		abort();
	t = ts.tv_sec + clock_step;
	if (tp != NULL)
		*tp = t;
	return t;
}

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

static void
write_file_n(const char *path, const char *data, size_t len)
{
	FILE *fp = fopen(path, "w");

	if (!fp) {
		perror(path);
		exit(1);
	}
	fwrite(data, 1, len, fp);
	fclose(fp);
}

/* Copy field n, counted from 0, of the row for ip in the file at path:
 * 3 is first_seen and 4 last_seen */
static void
saved_field(const char *path, const char *ip, int n, char *buf, size_t len)
{
	char line[256];
	size_t iplen = strlen(ip);
	FILE *fp = fopen(path, "r");

	if (!fp) {
		perror(path);
		exit(1);
	}
	while (fgets(line, sizeof(line), fp)) {
		char *p = line;

		if (strncmp(line, ip, iplen) != 0 || line[iplen] != ',')
			continue;
		for (int i = 0; i < n && p != NULL; i++)
			if ((p = strchr(p, ',')) != NULL)
				p++;
		if (p != NULL) {
			snprintf(buf, len, "%.*s", (int)strcspn(p, ","), p);
			fclose(fp);
			return;
		}
	}
	fprintf(stderr, "FAIL: no row for %s in %s\n", ip, path);
	exit(1);
}

static void
test_valid_csv(void)
{
	write_file(TEST_TMP,
	    "192.168.1.1,aa:bb:cc:dd:ee:ff,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "2001:db8::1,11:22:33:44:55:66,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00,"
	    "00:00:00:00:00:00\n");

	db_init();
	db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);
}

static void
test_empty_file(void)
{
	write_file(TEST_TMP, "");

	db_init();
	db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);
}

static void
test_malformed(void)
{
	write_file(TEST_TMP,
	    "not,a,valid,line\n"
	    "\n"
	    "# comment\n"
	    "192.168.1.1,ZZZZ,eth0,bad,bad\n"
	    "192.168.1.1,aa:bb:cc:dd:ee:ff,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n");

	db_init();
	db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);
}

static void
test_roundtrip(void)
{
	write_file(TEST_TMP,
	    "10.0.0.1,de:ad:be:ef:00:01,eth1,"
	    "2026-06-15T10:30:00,2026-06-15T11:00:00,"
	    "00:00:00:00:00:00\n"
	    "10.0.0.2,de:ad:be:ef:00:02,eth1,"
	    "2026-06-15T10:31:00,2026-06-15T11:01:00,"
	    "de:ad:be:ef:00:01\n");

	db_init();
	db_load(TEST_TMP);
	db_save(TEST_TMP2);
	db_free();

	/* reload saved file */
	db_init();
	db_load(TEST_TMP2);
	db_free();

	unlink(TEST_TMP);
	unlink(TEST_TMP2);
}

static void
test_bad_timestamp(void)
{
	int r;

	/* a row with a valid IP and MAC but an unparseable timestamp must
	 * be skipped, not kept with an epoch-0 time */
	write_file(TEST_TMP,
	    "192.168.5.5,aa:bb:cc:dd:ee:ff,eth0,bad,bad\n"
	    "192.168.5.6,aa:bb:cc:dd:ee:01,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n");

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != 1) {
		fprintf(stderr,
		    "FAIL: bad-timestamp row not skipped (loaded %d, want 1)\n",
		    r);
		exit(1);
	}
}

static void
test_same_ip_two_ifaces(void)
{
	int r;

	/* the same address on two interfaces must be kept as two distinct
	 * entries, not collapsed into one */
	write_file(TEST_TMP,
	    "fe80::1,aa:bb:cc:00:00:01,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00,00:00:00:00:00:00\n"
	    "fe80::1,aa:bb:cc:00:00:02,eth1,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00,00:00:00:00:00:00\n");

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != 2) {
		fprintf(stderr,
		    "FAIL: same IP on two interfaces not kept separate "
		    "(loaded %d, want 2)\n", r);
		exit(1);
	}
}

static void
test_symlink_rejected(void)
{
	int r;

	/* db_load must not follow a symlink at the final path component;
	 * otherwise a symlink planted in a writable DB directory redirects
	 * the root-time read to an arbitrary file */
	write_file(TEST_TMP2,
	    "192.168.9.9,aa:bb:cc:dd:ee:ff,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n");
	unlink(TEST_TMP);
	if (symlink("test_dbload2.tmp", TEST_TMP) != 0) {
		unlink(TEST_TMP2);
		return;   /* filesystem without symlink support: skip */
	}

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);
	unlink(TEST_TMP2);

	if (r != -1) {
		fprintf(stderr,
		    "FAIL: db_load followed a symlink (returned %d, want -1)\n",
		    r);
		exit(1);
	}
}

static void
test_fifo_rejected(void)
{
	int r;

	/* db_load must reject a FIFO promptly rather than blocking on open
	 * or looping forever on an endless read (a local DoS vector) */
	unlink(TEST_TMP);
	if (mkfifo(TEST_TMP, 0600) != 0)
		return;   /* mkfifo unsupported: skip */

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != -1) {
		fprintf(stderr,
		    "FAIL: db_load did not reject a FIFO (returned %d, want -1)\n",
		    r);
		exit(1);
	}
}

static void
test_mac_index(void)
{
	uint8_t macA[6] = { 0xaa, 0, 0, 0, 0, 1 };
	uint8_t macB[6] = { 0xbb, 0, 0, 0, 0, 2 };
	uint8_t ip1[16] = { 10, 0, 0, 1 };
	uint8_t ip2[16] = { 10, 0, 0, 2 };
	uint8_t ip3[16] = { 10, 0, 0, 3 };
	uint8_t old[6];
	time_t ols;
	struct db_entry_info others[8];
	char buf[256];
	int n;

	db_init();

	/* macA has two IPv4 addresses on eth0, macB has one */
	db_update(AF_INET, ip1, macA, "eth0", old, &ols);
	db_update(AF_INET, ip2, macA, "eth0", old, &ols);
	db_update(AF_INET, ip3, macB, "eth0", old, &ols);

	/* other entries of macA excluding ip1 -> ip2 only */
	n = db_find_other_entries(macA, AF_INET, ip1, others, 8);
	if (n != 1) {
		fprintf(stderr, "FAIL: mac index other-entries got %d, want 1\n",
		    n);
		exit(1);
	}
	n = db_other_ips(macA, AF_INET, ip1, buf, sizeof(buf));
	if (n != 1 || strcmp(buf, "10.0.0.2") != 0) {
		fprintf(stderr, "FAIL: db_other_ips got %d '%s'\n", n, buf);
		exit(1);
	}

	/* move ip2 from macA to macB: the index must follow the MAC change */
	db_update(AF_INET, ip2, macB, "eth0", old, &ols);
	if (db_find_other_entries(macA, AF_INET, ip1, others, 8) != 0) {
		fprintf(stderr, "FAIL: macA still lists a moved entry\n");
		exit(1);
	}
	if (db_find_other_entries(macB, AF_INET, ip3, others, 8) != 1) {
		fprintf(stderr, "FAIL: macB missing the moved entry\n");
		exit(1);
	}

	/* delete ip2: macB then has only ip3 */
	db_delete(AF_INET, ip2, macB, "eth0");
	if (db_find_other_entries(macB, AF_INET, ip3, others, 8) != 0) {
		fprintf(stderr, "FAIL: deleted entry still in mac index\n");
		exit(1);
	}

	db_free();
}

static void
test_mac_cap(void)
{
	uint8_t mac[6] = { 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33 };
	uint8_t ip[16];
	uint8_t old[6];
	time_t ols;
	int added = 0;

	db_init();

	/* many distinct addresses under one MAC: only MAX_PER_MAC are
	 * accepted, the rest refused, so a flood under one MAC cannot grow
	 * that MAC's chain (and per-packet work) without bound */
	memset(ip, 0, sizeof(ip));
	ip[0] = 0x20; ip[1] = 0x01; ip[2] = 0x0d; ip[3] = 0xb8;   /* 2001:db8::/64 */
	ip[8] = 0xde;
	for (int i = 0; i < MAX_PER_MAC + 50; i++) {
		ip[14] = (uint8_t)(i >> 8);
		ip[15] = (uint8_t)(i & 0xff);
		if (db_update(AF_INET6, ip, mac, "eth0", old, &ols) == EVENT_NEW)
			added++;
	}

	if (added != MAX_PER_MAC) {
		fprintf(stderr, "FAIL: per-MAC cap accepted %d, want %d\n",
		    added, MAX_PER_MAC);
		exit(1);
	}

	/* an address moving to the capped MAC is still reported, but its
	 * entry stays under its previous MAC instead of growing that
	 * MAC's chain */
	{
		uint8_t other[6] = { 0x02, 0, 0, 0, 0, 0x01 };
		uint8_t ip4[4] = { 10, 1, 2, 3 };
		uint8_t none[16] = { 0 };
		static struct db_entry_info info[MAX_PER_MAC + 8];
		int n;

		if (db_update(AF_INET, ip4, other, "eth0", old, &ols) !=
		    EVENT_NEW ||
		    db_update(AF_INET, ip4, mac, "eth0", old, &ols) !=
		    EVENT_CHANGED) {
			fprintf(stderr, "FAIL: change to capped MAC "
			    "not reported\n");
			exit(1);
		}
		n = db_find_other_entries(mac, AF_INET6, none, info,
		    MAX_PER_MAC + 8);
		n += db_find_other_entries(mac, AF_INET, none, info,
		    MAX_PER_MAC + 8);
		if (n != MAX_PER_MAC) {
			fprintf(stderr, "FAIL: capped MAC holds %d entries "
			    "after a change, want %d\n", n, MAX_PER_MAC);
			exit(1);
		}
		if (db_update(AF_INET, ip4, other, "eth0", old, &ols) != 0) {
			fprintf(stderr, "FAIL: entry did not keep its "
			    "previous MAC\n");
			exit(1);
		}
	}

	db_free();
}

static void
test_mac_cap_load(void)
{
	FILE *fp;
	int r;

	/* a file written before the cap existed may hold more addresses
	 * under one MAC; only MAX_PER_MAC of them are loaded */
	fp = fopen(TEST_TMP, "w");
	if (!fp) {
		perror(TEST_TMP);
		exit(1);
	}
	for (int i = 0; i < MAX_PER_MAC + 40; i++)
		fprintf(fp, "10.2.%d.%d,02:00:00:00:00:99,eth0,"
		    "2026-01-01T00:00:00,2026-01-02T00:00:00\n",
		    i / 250, 1 + i % 250);
	fclose(fp);

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != MAX_PER_MAC) {
		fprintf(stderr, "FAIL: load kept %d entries under one MAC, "
		    "want %d\n", r, MAX_PER_MAC);
		exit(1);
	}
}

/* rows dated before the epoch are skipped */
static void
test_pre_epoch(void)
{
	int r;

	write_file(TEST_TMP,
	    "10.4.0.1,02:00:00:00:00:01,eth0,"
	    "1950-01-01T00:00:00,1950-01-02T00:00:00\n"
	    "10.4.0.2,02:00:00:00:00:02,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n");

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != 1) {
		fprintf(stderr, "FAIL: pre-epoch row: loaded %d, want 1\n", r);
		exit(1);
	}
}

/* a row whose interface field holds control bytes is skipped */
static void
test_control_bytes_iface(void)
{
	int r;

	write_file(TEST_TMP,
	    "10.3.0.1,02:00:00:00:00:01,eth0\033]0;x\007,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n"
	    "10.3.0.2,02:00:00:00:00:02,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n"
	    "10.3.0.3,02:00:00:00:00:03,eth\2330m,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n");

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != 1) {
		fprintf(stderr, "FAIL: control bytes in iface: loaded %d, "
		    "want 1\n", r);
		exit(1);
	}
}

/* a station recorded 200 days ago reappears at its first sighting, and
 * not again at the next one: once seen, its silence is measured on the
 * monotonic clock */
static void
test_reappeared(void)
{
	uint8_t ip[4] = { 10, 0, 0, 2 };
	uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x02 };
	uint8_t old[6];
	char line[160], when[32];
	time_t then = time(NULL) - 200 * 24 * 3600, ols = 0;
	struct tm tm;

	localtime_r(&then, &tm);
	strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(line, sizeof(line), "10.0.0.2,de:ad:be:ef:00:02,eth1,"
	    "%s,%s,00:00:00:00:00:00\n", when, when);
	write_file(TEST_TMP, line);

	db_init();
	db_load(TEST_TMP);
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) !=
	    EVENT_REAPPEARED || ols != then) {
		fprintf(stderr, "FAIL: station silent 200 days did not "
		    "reappear\n");
		exit(1);
	}
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) != 0) {
		fprintf(stderr, "FAIL: station reappeared twice\n");
		exit(1);
	}
	db_free();
	unlink(TEST_TMP);
}

/* A wall clock still behind at a sighting, as on a board without a
 * real-time clock before NTP sets it, does not replace the last_seen time
 * read from the file. Once it is set right, a station first seen while it
 * was behind does not reappear: its silence is measured on the monotonic
 * clock. */
static void
test_clock_behind(void)
{
	uint8_t ip[4] = { 10, 0, 0, 3 }, ip2[4] = { 10, 0, 0, 4 };
	uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x03 };
	uint8_t old[6];
	char line[160], when[32], saved[32];
	time_t then = time(NULL) - 60, ols;
	struct tm tm;

	localtime_r(&then, &tm);
	strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(line, sizeof(line), "10.0.0.3,de:ad:be:ef:00:03,eth1,"
	    "%s,%s,00:00:00:00:00:00\n", when, when);
	write_file(TEST_TMP, line);

	db_init();
	db_load(TEST_TMP);
	clock_step = -365 * 24 * 3600;
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) != 0 ||
	    db_update(AF_INET, ip, mac, "eth1", old, &ols) != 0 ||
	    db_update(AF_INET, ip2, mac, "eth1", old, &ols) != EVENT_NEW) {
		fprintf(stderr, "FAIL: wrong event with the clock behind\n");
		exit(1);
	}
	db_save(TEST_TMP2);
	saved_field(TEST_TMP2, "10.0.0.3", 4, saved, sizeof(saved));
	if (strcmp(saved, when) != 0) {
		fprintf(stderr, "FAIL: a clock behind moved last_seen back "
		    "from %s to %s\n", when, saved);
		exit(1);
	}
	clock_step = 0;
	if (db_update(AF_INET, ip2, mac, "eth1", old, &ols) != 0) {
		fprintf(stderr, "FAIL: a station seen with the clock behind "
		    "reappeared once it was set right\n");
		exit(1);
	}
	db_free();
	unlink(TEST_TMP);
	unlink(TEST_TMP2);
}

/* A sighting made while the wall clock was ahead, as with a bad real-time
 * clock, is placed by the monotonic clock once the clock is set back: its
 * last_seen time is not left in the future, first_seen is not written
 * after it, nor moved by later sightings, and it can expire. */
static void
test_clock_ahead(void)
{
	uint8_t ip[4] = { 10, 0, 0, 5 }, ip2[4] = { 10, 0, 0, 6 };
	uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x05 };
	uint8_t old[6];
	char saved[32], first[32], lo[32], hi[32], hi1[32];
	time_t t, ols;
	struct tm tm;

	db_init();
	t = time(NULL) - 1;
	localtime_r(&t, &tm);
	strftime(lo, sizeof(lo), "%Y-%m-%dT%H:%M:%S", &tm);
	t = time(NULL) + 1;
	localtime_r(&t, &tm);
	strftime(hi1, sizeof(hi1), "%Y-%m-%dT%H:%M:%S", &tm);
	clock_step = 365 * 24 * 3600;
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) != EVENT_NEW ||
	    db_update(AF_INET, ip2, mac, "eth1", old, &ols) != EVENT_NEW) {
		fprintf(stderr, "FAIL: wrong event with the clock ahead\n");
		exit(1);
	}
	/* seen again before the clock is set right */
	sleep(2);
	if (db_update(AF_INET, ip2, mac, "eth1", old, &ols) != 0) {
		fprintf(stderr, "FAIL: wrong event with the clock ahead\n");
		exit(1);
	}
	clock_step = 0;
	db_save(TEST_TMP);
	t = time(NULL) + 1;
	localtime_r(&t, &tm);
	strftime(hi, sizeof(hi), "%Y-%m-%dT%H:%M:%S", &tm);
	saved_field(TEST_TMP, "10.0.0.5", 4, saved, sizeof(saved));
	if (strcmp(saved, lo) < 0 || strcmp(saved, hi) > 0) {
		fprintf(stderr, "FAIL: last_seen %s of a sighting with the "
		    "clock ahead is not between %s and %s\n", saved, lo, hi);
		exit(1);
	}
	saved_field(TEST_TMP, "10.0.0.5", 3, first, sizeof(first));
	if (strcmp(first, saved) > 0) {
		fprintf(stderr, "FAIL: first_seen %s written after last_seen "
		    "%s\n", first, saved);
		exit(1);
	}
	sleep(3);
	if (db_update(AF_INET, ip2, mac, "eth1", old, &ols) != 0 ||
	    db_expire(1) != 1) {
		fprintf(stderr, "FAIL: an entry seen with the clock ahead "
		    "did not expire\n");
		exit(1);
	}
	db_save(TEST_TMP);
	saved_field(TEST_TMP, "10.0.0.6", 3, first, sizeof(first));
	if (strcmp(first, lo) < 0 || strcmp(first, hi1) > 0) {
		fprintf(stderr, "FAIL: first_seen %s of a station first seen "
		    "with the clock ahead is not between %s and %s\n", first,
		    lo, hi1);
		exit(1);
	}
	db_free();
	unlink(TEST_TMP);
}

/* A clock stepped back for a while and then set right again does not
 * move the first sighting of a station made before the step. */
static void
test_clock_back(void)
{
	uint8_t ip[4] = { 10, 0, 0, 7 };
	uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x07 };
	uint8_t old[6];
	char first[32], lo[32], hi[32];
	time_t t, ols;
	struct tm tm;

	db_init();
	t = time(NULL) - 1;
	localtime_r(&t, &tm);
	strftime(lo, sizeof(lo), "%Y-%m-%dT%H:%M:%S", &tm);
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) != EVENT_NEW) {
		fprintf(stderr, "FAIL: station not new\n");
		exit(1);
	}
	t = time(NULL) + 1;
	localtime_r(&t, &tm);
	strftime(hi, sizeof(hi), "%Y-%m-%dT%H:%M:%S", &tm);
	clock_step = -3600;
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) != 0) {
		fprintf(stderr, "FAIL: wrong event with the clock behind\n");
		exit(1);
	}
	clock_step = 0;
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) != 0) {
		fprintf(stderr, "FAIL: wrong event with the clock set right\n");
		exit(1);
	}
	db_save(TEST_TMP);
	saved_field(TEST_TMP, "10.0.0.7", 3, first, sizeof(first));
	if (strcmp(first, lo) < 0 || strcmp(first, hi) > 0) {
		fprintf(stderr, "FAIL: first_seen %s of a station made before "
		    "the clock was stepped back is not between %s and %s\n",
		    first, lo, hi);
		exit(1);
	}
	db_free();
	unlink(TEST_TMP);
}

/* a refresh of last_seen changes no event but must mark the table for
 * saving, and a save clears the mark */
static void
test_dirty(void)
{
	uint8_t ip[4] = { 10, 0, 0, 1 };
	uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
	uint8_t old[6];
	time_t ols;

	write_file(TEST_TMP,
	    "10.0.0.1,de:ad:be:ef:00:01,eth1,"
	    "2026-06-15T10:30:00,2026-06-15T11:00:00,"
	    "00:00:00:00:00:00\n");

	db_init();
	db_load(TEST_TMP);
	if (db_dirty()) {
		fprintf(stderr, "FAIL: freshly loaded table is dirty\n");
		exit(1);
	}
	if (db_update(AF_INET, ip, mac, "eth1", old, &ols) != 0 ||
	    !db_dirty()) {
		fprintf(stderr, "FAIL: last_seen refresh not marked dirty\n");
		exit(1);
	}
	if (db_save(TEST_TMP2) != 1 || db_dirty()) {
		fprintf(stderr, "FAIL: save did not clear the dirty mark\n");
		exit(1);
	}
	if (!db_delete(AF_INET, ip, mac, "eth1") || !db_dirty()) {
		fprintf(stderr, "FAIL: delete not marked dirty\n");
		exit(1);
	}
	db_free();
	if (db_dirty()) {
		fprintf(stderr, "FAIL: db_free left the dirty mark\n");
		exit(1);
	}
	unlink(TEST_TMP);
	unlink(TEST_TMP2);
}

static void
test_nonexistent(void)
{
	db_init();
	db_load("tmp/test_dbload_no_such_file.csv");
	db_free();
}

static void
test_oversized_line(void)
{
	char big[800];
	int r;

	/* an over-long first physical line (no newline within the read
	 * buffer) must be drained and skipped, not split into bogus
	 * records, and the following valid line must still load */
	memset(big, 'x', 511);
	snprintf(big + 511, sizeof(big) - 511,
	    "10.9.9.9,aa:bb:cc:dd:ee:ff,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n"
	    "10.9.9.10,aa:bb:cc:dd:ee:01,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n");
	write_file(TEST_TMP, big);

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != 1) {
		fprintf(stderr,
		    "FAIL: oversized line not skipped (loaded %d, want 1)\n", r);
		exit(1);
	}
}

static void
test_embedded_nul_line(void)
{
	char buf[700];
	size_t n = 0;
	const char *rec = "10.9.9.9,aa:bb:cc:dd:ee:ff,eth0,"
	    "2026-01-01T00:00:00,2026-01-02T00:00:00\n";
	int r;

	/* an over-long line carrying a NUL at the old sentinel position
	 * (index 510) must still be skipped whole; the byte-counting
	 * reader must not let the bytes after the NUL parse as a record */
	memset(buf, 'x', 510);
	n = 510;
	buf[n++] = '\0';
	memcpy(buf + n, rec, strlen(rec));
	n += strlen(rec);
	write_file_n(TEST_TMP, buf, n);

	db_init();
	r = db_load(TEST_TMP);
	db_free();
	unlink(TEST_TMP);

	if (r != 0) {
		fprintf(stderr,
		    "FAIL: embedded-NUL over-long line not skipped "
		    "(loaded %d, want 0)\n", r);
		exit(1);
	}
}

int
main(void)
{
	cfg.quiet = 1;
	mkdir("tmp", 0755);

	test_valid_csv();
	test_empty_file();
	test_malformed();
	test_roundtrip();
	test_bad_timestamp();
	test_same_ip_two_ifaces();
	test_symlink_rejected();
	test_fifo_rejected();
	test_mac_index();
	test_mac_cap();
	test_mac_cap_load();
	test_control_bytes_iface();
	test_pre_epoch();
	test_dirty();
	test_reappeared();
	test_clock_behind();
	test_clock_ahead();
	test_clock_back();
	test_nonexistent();
	test_oversized_line();
	test_embedded_nul_line();

	printf("test_dbload: all tests passed\n");
	return 0;
}
