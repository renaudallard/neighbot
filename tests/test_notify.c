/*
 * Test harness for format_delta() and format_timestamp().
 * Designed to run under valgrind for leak checking.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "../neighbot.h"
#include "../notify.h"

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
test_format_delta(void)
{
	char buf[64];

	format_delta(0, buf, sizeof(buf));
	ASSERT(strcmp(buf, "0 seconds") == 0, "delta 0");

	format_delta(30, buf, sizeof(buf));
	ASSERT(strcmp(buf, "30 seconds") == 0, "delta 30s");

	format_delta(61, buf, sizeof(buf));
	ASSERT(strcmp(buf, "1 minutes") == 0, "delta 61s");

	format_delta(3601, buf, sizeof(buf));
	ASSERT(strcmp(buf, "1 hours") == 0, "delta 3601s");

	format_delta(86401, buf, sizeof(buf));
	ASSERT(strcmp(buf, "1 days") == 0, "delta 86401s");

	format_delta(-5, buf, sizeof(buf));
	ASSERT(strcmp(buf, "0 seconds") == 0, "delta negative clamp");

	printf("  format_delta: ok\n");
	return 0;
}

static int
test_format_timestamp(void)
{
	char buf[128];

	setenv("TZ", "UTC", 1);
	tzset();

	format_timestamp(0, buf, sizeof(buf));
	ASSERT(strstr(buf, "January") != NULL, "epoch should contain January");
	ASSERT(strstr(buf, "1970") != NULL, "epoch should contain 1970");
	ASSERT(strstr(buf, "00:00:00") != NULL, "epoch should contain 00:00:00");
	ASSERT(strstr(buf, "+0000") != NULL, "epoch UTC should contain +0000");

	printf("  format_timestamp: ok\n");
	return 0;
}

int
main(void)
{
	int rc = 0;

	cfg.quiet = 1;

	printf("test_notify:\n");
	rc |= test_format_delta();
	rc |= test_format_timestamp();

	if (rc == 0)
		printf("test_notify: all tests passed\n");
	return rc;
}
