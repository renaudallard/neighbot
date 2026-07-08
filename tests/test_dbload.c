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
	test_same_ip_two_ifaces();
	test_nonexistent();
	test_oversized_line();
	test_embedded_nul_line();

	printf("test_dbload: all tests passed\n");
	return 0;
}
