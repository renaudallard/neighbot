/*
 * Test harness for db_expire / db_expire_temp.
 * Loads CSV entries with controlled timestamps and verifies which ones
 * the reapers drop.  Designed to run under valgrind for leak checking.
 */

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../neighbot.h"
#include "../db.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

#define TEST_TMP "/tmp/test_dbexpire.tmp"

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
fmt_ts(time_t t, char *buf, size_t len)
{
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

static void
test_expire_temp_basic(void)
{
	/* Four entries all with last_seen in 2020:
	 *   - EUI-64 IPv6 (interface ID matches MAC): kept
	 *   - link-local fe80:: IPv6: kept
	 *   - non-EUI-64 non-link-local IPv6: reaped
	 *   - IPv4: kept
	 */
	write_file(TEST_TMP,
	    "fd00::a8bb:ccff:fedd:eeff,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fe80::1,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd00::1234:5678:9abc:def0,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "192.168.1.1,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n");

	db_init();
	assert(db_load(TEST_TMP) == 4);
	assert(db_expire_temp(7 * 24 * 3600) == 1);
	db_free();
	unlink(TEST_TMP);
}

static void
test_expire_temp_keeps_fresh(void)
{
	char line[512];
	char first_str[32], last_str[32];
	time_t now = time(NULL);

	fmt_ts(now, first_str, sizeof(first_str));
	fmt_ts(now, last_str, sizeof(last_str));

	snprintf(line, sizeof(line),
	    "fd00::1234:5678:9abc:def0,aa:bb:cc:dd:ee:ff,eth0,"
	    "%s,%s,00:00:00:00:00:00\n", first_str, last_str);

	write_file(TEST_TMP, line);

	db_init();
	assert(db_load(TEST_TMP) == 1);
	assert(db_expire_temp(7 * 24 * 3600) == 0);
	db_free();
	unlink(TEST_TMP);
}

static void
test_expire_temp_multiple_stale(void)
{
	/* Mirror the field-reported case: a single MAC with ten stale
	 * non-EUI-64 IPv6 entries across two prefixes plus a fresh
	 * EUI-64 address and an IPv4 address.  Only the ten stale
	 * temporaries should be reaped. */
	write_file(TEST_TMP,
	    "fd74:8e83:4254:c6b0:9e07:4e6f:dc16:3134,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:9d3e:6ae2:4382:db78,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:e507:e272:6d38:3e77,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:b4a1:e3ac:ec24:c601,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:569a:c0ab:fe7f:443d,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:67b3:9d70:7f5:780d,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:5fe7:1729:3aef:bd14,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:8025:130f:6a51:3e49,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "2a02:a018:8b:af00:f186:c2b6:f2f0:cb56,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "2a02:a018:8b:af00:ca21:c792:c7f7:9f50,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "fd74:8e83:4254:c6b0:a8bb:ccff:fedd:eeff,"
	    "aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "192.168.1.10,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n");

	db_init();
	assert(db_load(TEST_TMP) == 12);
	assert(db_expire_temp(7 * 24 * 3600) == 10);
	db_free();
	unlink(TEST_TMP);
}

static void
test_expire_temp_disabled(void)
{
	/* Negative or zero threshold disables the sweep. */
	write_file(TEST_TMP,
	    "fd00::1234:5678:9abc:def0,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n");

	db_init();
	assert(db_load(TEST_TMP) == 1);
	assert(db_expire_temp(0) == 0);
	assert(db_expire_temp(-1) == 0);
	db_free();
	unlink(TEST_TMP);
}

static void
test_expire_idle(void)
{
	/* db_expire reaps EVERY idle entry regardless of family. */
	write_file(TEST_TMP,
	    "fd00::a8bb:ccff:fedd:eeff,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n"
	    "192.168.1.1,aa:bb:cc:dd:ee:ff,eth0,"
	    "2020-01-01T00:00:00,2020-01-02T00:00:00,"
	    "00:00:00:00:00:00\n");

	db_init();
	assert(db_load(TEST_TMP) == 2);
	assert(db_expire(30 * 24 * 3600) == 2);
	db_free();
	unlink(TEST_TMP);
}

int
main(void)
{
	cfg.quiet = 1;

	test_expire_temp_basic();
	test_expire_temp_keeps_fresh();
	test_expire_temp_multiple_stale();
	test_expire_temp_disabled();
	test_expire_idle();

	printf("test_dbexpire: all tests passed\n");
	return 0;
}
