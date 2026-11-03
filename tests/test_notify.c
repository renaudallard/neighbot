/*
 * Test harness for format_delta(), format_timestamp() and the count of
 * notification children. notify.c is included to see that count.
 * Designed to run under valgrind for leak checking.
 */

#include <sys/types.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "../notify.c"

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
	ASSERT(strcmp(buf, "1 minute") == 0, "delta 61s");

	format_delta(3601, buf, sizeof(buf));
	ASSERT(strcmp(buf, "1 hour") == 0, "delta 3601s");

	format_delta(86401, buf, sizeof(buf));
	ASSERT(strcmp(buf, "1 day") == 0, "delta 86401s");

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

static void
pause_10ms(void)
{
	struct timespec ts = { 0, 10 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/*
 * Only notification children are counted against the cap: reaping
 * another child, as one a launcher left or an orphan handed to neighbot
 * as PID 1 of a namespace, frees no slot.
 */
static int
test_child_count(void)
{
	int p[2], started = 0, i;
	pid_t other;

	/* children inherit unwritten output, which valgrind flushes when
	 * each one exits */
	fflush(stdout);
	ASSERT(pipe(p) == 0, "pipe");
	for (i = 0; i < NOTIFY_MAX_INFLIGHT; i++) {
		int r = notify_fork();

		if (r == 0) {
			char c;

			close(p[1]);
			if (read(p[0], &c, 1) < 0)
				_exit(1);
			_exit(0);
		}
		started += r == 1;
	}
	ASSERT(started == NOTIFY_MAX_INFLIGHT, "children up to the cap");

	other = fork();
	if (other == 0)
		_exit(0);
	ASSERT(other > 0, "fork");
	for (i = 0; i < 500 && kill(other, 0) == 0; i++) {
		notify_reap_children();
		pause_10ms();
	}
	ASSERT(kill(other, 0) < 0 && errno == ESRCH, "other child not reaped");
	ASSERT(notify_inflight == NOTIFY_MAX_INFLIGHT,
	    "another child freed a notification slot");

	close(p[0]);
	close(p[1]);
	for (i = 0; i < 500 && notify_inflight > 0; i++) {
		notify_reap_children();
		pause_10ms();
	}
	ASSERT(notify_inflight == 0, "notification children not counted down");

	printf("  child count: ok\n");
	return 0;
}

/* A child that has ended but is not reaped yet frees its slot when a
 * notification is due at the cap: it is reaped first. */
static int
test_reap_at_cap(void)
{
	siginfo_t si;
	int i, r;

	fflush(stdout);
	for (i = 0; i < NOTIFY_MAX_INFLIGHT; i++) {
		r = notify_fork();
		if (r == 0)
			_exit(0);
		ASSERT(r == 1, "children up to the cap");
	}
	/* let them all end, without reaping them */
	for (i = 0; i < NOTIFY_MAX_INFLIGHT; i++) {
		memset(&si, 0, sizeof(si));
		while (waitid(P_PID, (id_t)notify_pids[i], &si,
		    WEXITED | WNOWAIT) < 0 && errno == EINTR)
			;
	}
	r = notify_fork();
	if (r == 0)
		_exit(0);
	ASSERT(r == 1, "a notification was refused with no child running");
	for (i = 0; i < 500 && notify_inflight > 0; i++) {
		notify_reap_children();
		pause_10ms();
	}
	ASSERT(notify_inflight == 0, "notification children not counted down");

	printf("  reap at the cap: ok\n");
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
	/* as reset_signals() does for the daemon: an ignored SIGCHLD
	 * would have the children reaped before notify_reap_children() */
	signal(SIGCHLD, SIG_DFL);
	rc |= test_child_count();
	rc |= test_reap_at_cap();

	if (rc == 0)
		printf("test_notify: all tests passed\n");
	return rc;
}
