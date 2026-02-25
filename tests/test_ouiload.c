/*
 * Test harness for oui_load / oui_lookup / oui_free.
 * Exercises the OUI vendor database with known inputs.
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../neighbot.h"
#include "../oui.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

#define TEST_TMP "/tmp/test_ouiload.tmp"

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
test_neighbot_format(void)
{
	write_file(TEST_TMP,
	    "aa:bb:cc Acme Corp\n"
	    "11:22:33 Widgets Inc\n"
	    "de:ad:be Evil Corp\n");

	oui_load(TEST_TMP);

	/* lookup hit */
	uint8_t mac1[6] = { 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03 };
	const char *v = oui_lookup(mac1);
	if (!v || strcmp(v, "Acme Corp") != 0) {
		fprintf(stderr, "test_neighbot_format: expected 'Acme Corp', "
		    "got '%s'\n", v ? v : "(null)");
		exit(1);
	}

	/* lookup miss */
	uint8_t mac2[6] = { 0xff, 0xff, 0xff, 0x01, 0x02, 0x03 };
	if (oui_lookup(mac2) != NULL) {
		fprintf(stderr, "test_neighbot_format: expected NULL for miss\n");
		exit(1);
	}

	oui_free();
	unlink(TEST_TMP);
}

static void
test_arpscan_format(void)
{
	write_file(TEST_TMP,
	    "AABBCC\tAcme Corp\n"
	    "112233\tWidgets Inc\n");

	oui_load(TEST_TMP);

	uint8_t mac[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	const char *v = oui_lookup(mac);
	if (!v || strcmp(v, "Widgets Inc") != 0) {
		fprintf(stderr, "test_arpscan_format: expected 'Widgets Inc', "
		    "got '%s'\n", v ? v : "(null)");
		exit(1);
	}

	oui_free();
	unlink(TEST_TMP);
}

static void
test_empty_file(void)
{
	write_file(TEST_TMP, "");

	oui_load(TEST_TMP);

	uint8_t mac[6] = { 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03 };
	if (oui_lookup(mac) != NULL) {
		fprintf(stderr, "test_empty_file: expected NULL\n");
		exit(1);
	}

	oui_free();
	unlink(TEST_TMP);
}

static void
test_nonexistent(void)
{
	oui_load("/tmp/test_ouiload_no_such_file.txt");
	oui_free();
}

int
main(void)
{
	cfg.quiet = 1;

	test_neighbot_format();
	test_arpscan_format();
	test_empty_file();
	test_nonexistent();

	printf("test_ouiload: all tests passed\n");
	return 0;
}
