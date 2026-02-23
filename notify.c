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

#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "neighbot.h"
#include "db.h"
#include "log.h"
#include "notify.h"
#include "oui.h"

static void
resolve_hostname(int af, const uint8_t *ip, char *host, size_t hostlen)
{
	struct sockaddr_storage ss;
	socklen_t sslen;

	memset(&ss, 0, sizeof(ss));

	if (af == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, ip, 4);
		sslen = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, ip, 16);
		sslen = sizeof(*sin6);
	}

	if (getnameinfo((struct sockaddr *)&ss, sslen,
	                host, hostlen, NULL, 0, NI_NAMEREQD) != 0)
		snprintf(host, hostlen, "<unknown>");
}

static void
format_mac(const uint8_t *mac, char *buf, size_t len)
{
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void
format_timestamp(time_t t, char *buf, size_t len)
{
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(buf, len, "%A, %B %d, %Y %H:%M:%S %z", &tm);
}

static void
format_delta(time_t delta, char *buf, size_t len)
{
	long d = (long)delta;

	if (d < 60)
		snprintf(buf, len, "%ld seconds", d);
	else if (d < 3600)
		snprintf(buf, len, "%ld minutes", d / 60);
	else if (d < 86400)
		snprintf(buf, len, "%ld hours", d / 3600);
	else
		snprintf(buf, len, "%ld days", d / 86400);
}

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

		/* close inherited fds (pcap handles) before exec */
		long maxfd = sysconf(_SC_OPEN_MAX);
		if (maxfd <= 0)
			maxfd = 256;
		for (long i = STDERR_FILENO + 1; i < maxfd; i++)
			close((int)i);

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
notify_new(int af, const uint8_t *ip, const uint8_t *mac,
           const char *iface)
{
	char subject[256];
	char body[2048];
	char ipstr[INET6_ADDRSTRLEN];
	char macstr[18];
	char host[256];
	char timebuf[128];
	char other_ips[512];
	const char *vendor;
	size_t off;

	inet_ntop(af, ip, ipstr, sizeof(ipstr));
	format_mac(mac, macstr, sizeof(macstr));
	resolve_hostname(af, ip, host, sizeof(host));
	format_timestamp(time(NULL), timebuf, sizeof(timebuf));
	vendor = oui_lookup(mac);

	snprintf(subject, sizeof(subject),
	         "neighbot: new station %s on %s", ipstr, iface);
	off = snprintf(body, sizeof(body),
	         "          hostname: %s\n"
	         "        ip address: %s\n"
	         "  ethernet address: %s\n"
	         "   ethernet vendor: %s\n"
	         "         timestamp: %s\n",
	         host, ipstr, macstr,
	         vendor ? vendor : "<unknown>",
	         timebuf);

	if (db_other_ips(mac, af, ip, other_ips, sizeof(other_ips)) > 0)
		snprintf(body + off, sizeof(body) - off,
		         "     also known as: %s\n", other_ips);

	send_mail(subject, body);
}

void
notify_changed(int af, const uint8_t *ip, const uint8_t *mac,
               const uint8_t *old_mac, const char *iface,
               time_t prev_seen)
{
	char subject[256];
	char body[2048];
	char ipstr[INET6_ADDRSTRLEN];
	char macstr[18], oldmacstr[18];
	char host[256];
	char timebuf[128], prevbuf[128], deltabuf[64];
	char other_ips[512];
	const char *vendor, *old_vendor;
	time_t now = time(NULL);
	size_t off;

	inet_ntop(af, ip, ipstr, sizeof(ipstr));
	format_mac(mac, macstr, sizeof(macstr));
	format_mac(old_mac, oldmacstr, sizeof(oldmacstr));
	resolve_hostname(af, ip, host, sizeof(host));
	format_timestamp(now, timebuf, sizeof(timebuf));
	format_timestamp(prev_seen, prevbuf, sizeof(prevbuf));
	format_delta(now - prev_seen, deltabuf, sizeof(deltabuf));
	vendor = oui_lookup(mac);
	old_vendor = oui_lookup(old_mac);

	snprintf(subject, sizeof(subject),
	         "neighbot: changed station %s on %s", ipstr, iface);
	off = snprintf(body, sizeof(body),
	         "             hostname: %s\n"
	         "           ip address: %s\n"
	         "    ethernet address: %s\n"
	         "     ethernet vendor: %s\n"
	         "old ethernet address: %s\n"
	         " old ethernet vendor: %s\n"
	         "           timestamp: %s\n"
	         "  previous timestamp: %s\n"
	         "               delta: %s\n",
	         host, ipstr, macstr,
	         vendor ? vendor : "<unknown>",
	         oldmacstr,
	         old_vendor ? old_vendor : "<unknown>",
	         timebuf, prevbuf, deltabuf);

	if (db_other_ips(mac, af, ip, other_ips, sizeof(other_ips)) > 0)
		snprintf(body + off, sizeof(body) - off,
		         "       also known as: %s\n", other_ips);

	send_mail(subject, body);
}
