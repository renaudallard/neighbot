/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "neighbot.h"
#include "log.h"
#include "notify.h"

static void
send_mail(const char *subject, const char *body)
{
	int pfd[2];
	pid_t pid;

	if (pipe(pfd) < 0) {
		log_err("notify: pipe: %s", strerror(errno));
		return;
	}

	pid = fork();
	if (pid < 0) {
		log_err("notify: fork: %s", strerror(errno));
		close(pfd[0]);
		close(pfd[1]);
		return;
	}

	if (pid == 0) {
		/* child */
		close(pfd[1]);
		dup2(pfd[0], STDIN_FILENO);
		close(pfd[0]);
		execl("/usr/sbin/sendmail", "sendmail", "-t", (char *)NULL);
		_exit(127);
	}

	/* parent */
	close(pfd[0]);

	dprintf(pfd[1], "To: %s\n", cfg.mailto);
	dprintf(pfd[1], "Subject: %s\n", subject);
	dprintf(pfd[1], "Content-Type: text/plain; charset=utf-8\n");
	dprintf(pfd[1], "\n");
	dprintf(pfd[1], "%s", body);
	close(pfd[1]);

	int status;
	if (waitpid(pid, &status, 0) < 0)
		log_err("notify: waitpid: %s", strerror(errno));
	else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		log_err("notify: sendmail exited with status %d",
		        WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

void
notify_new(const char *ip, const char *mac, const char *iface)
{
	char subject[256];
	char body[512];
	char timebuf[64];
	time_t now = time(NULL);
	struct tm tm;

	localtime_r(&now, &tm);
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

	snprintf(subject, sizeof(subject),
	         "neighbot: new station %s", ip);
	snprintf(body, sizeof(body),
	         "New station detected:\n"
	         "  IP:        %s\n"
	         "  MAC:       %s\n"
	         "  Interface: %s\n"
	         "  Time:      %s\n",
	         ip, mac, iface, timebuf);

	send_mail(subject, body);
}

void
notify_changed(const char *ip, const char *old_mac,
               const char *new_mac, const char *iface)
{
	char subject[256];
	char body[512];
	char timebuf[64];
	time_t now = time(NULL);
	struct tm tm;

	localtime_r(&now, &tm);
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

	snprintf(subject, sizeof(subject),
	         "neighbot: changed station %s", ip);
	snprintf(body, sizeof(body),
	         "Station MAC address changed:\n"
	         "  IP:        %s\n"
	         "  Old MAC:   %s\n"
	         "  New MAC:   %s\n"
	         "  Interface: %s\n"
	         "  Time:      %s\n",
	         ip, old_mac, new_mac, iface, timebuf);

	send_mail(subject, body);
}
