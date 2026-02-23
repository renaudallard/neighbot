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
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "neighbot.h"
#include "capture.h"
#include "db.h"
#include "log.h"
#include "parse.h"

struct config cfg = {
	.daemonize = 0,
	.quiet     = 0,
	.dbfile    = NULL,
	.mailto    = NULL,
	.user      = NULL,
};

volatile sig_atomic_t quit;
volatile sig_atomic_t save;

static void
sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		quit = 1;
	else if (sig == SIGHUP)
		save = 1;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: neighbot [-d] [-f dbfile] [-m mailto] [-q] [-u user]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct iface ifaces[MAX_IFACES];
	struct pollfd pfds[MAX_IFACES];
	int nifaces, ch;

	cfg.dbfile = DEFAULT_DBFILE;
	cfg.mailto = DEFAULT_MAILTO;
	cfg.user   = DEFAULT_USER;

	while ((ch = getopt(argc, argv, "df:m:qu:")) != -1) {
		switch (ch) {
		case 'd':
			cfg.daemonize = 1;
			break;
		case 'f':
			cfg.dbfile = optarg;
			break;
		case 'm':
			cfg.mailto = optarg;
			break;
		case 'q':
			cfg.quiet = 1;
			break;
		case 'u':
			cfg.user = optarg;
			break;
		default:
			usage();
		}
	}

	if (optind != argc)
		usage();

	log_init("neighbot", cfg.daemonize);

	/* signals */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	db_init();
	db_load(cfg.dbfile);

	nifaces = capture_open_all(ifaces, MAX_IFACES);
	if (nifaces <= 0) {
		log_err("no usable interfaces found");
		db_free();
		return 1;
	}

	if (cfg.daemonize) {
		if (daemon(1, 0) < 0) {
			log_err("daemon: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			return 1;
		}
		/* re-init logging after daemon() closes stderr */
		log_init("neighbot", 1);
	}

	/* drop privileges */
	{
		struct passwd *pw = getpwnam(cfg.user);
		if (!pw) {
			log_err("unknown user: %s", cfg.user);
			capture_close_all(ifaces, nifaces);
			db_free();
			return 1;
		}

		/* chown DB directory and file so the target user can write */
		const char *sl = strrchr(cfg.dbfile, '/');
		char dbdir[PATH_MAX];
		if (sl && sl != cfg.dbfile)
			snprintf(dbdir, sizeof(dbdir), "%.*s",
			    (int)(sl - cfg.dbfile), cfg.dbfile);
		else if (sl)
			snprintf(dbdir, sizeof(dbdir), "/");
		else
			snprintf(dbdir, sizeof(dbdir), ".");

		if (chown(dbdir, pw->pw_uid, pw->pw_gid) < 0)
			log_err("chown %s: %s", dbdir, strerror(errno));
		(void)chown(cfg.dbfile, pw->pw_uid, pw->pw_gid);

		if (setgroups(1, &pw->pw_gid) < 0) {
			log_err("setgroups: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			return 1;
		}
		if (setgid(pw->pw_gid) < 0) {
			log_err("setgid: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			return 1;
		}
		if (setuid(pw->pw_uid) < 0) {
			log_err("setuid: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			return 1;
		}

		log_msg("dropped privileges to %s", cfg.user);
	}

	log_msg("neighbot %s started, monitoring %d interface(s)",
	        NEIGHBOT_VERSION, nifaces);

	/* build pollfd array */
	for (int i = 0; i < nifaces; i++) {
		pfds[i].fd = ifaces[i].fd;
		pfds[i].events = POLLIN;
	}

#ifdef __OpenBSD__
	/* prime timezone cache before pledge */
	tzset();

	if (cfg.quiet) {
		const char *sl;
		char dbdir[PATH_MAX];

		sl = strrchr(cfg.dbfile, '/');
		if (sl && sl != cfg.dbfile)
			snprintf(dbdir, sizeof(dbdir), "%.*s",
			    (int)(sl - cfg.dbfile), cfg.dbfile);
		else if (sl)
			snprintf(dbdir, sizeof(dbdir), "/");
		else
			snprintf(dbdir, sizeof(dbdir), ".");

		if (unveil(dbdir, "rwc") == -1)
			log_err("unveil %s: %s", dbdir, strerror(errno));
		else if (unveil(NULL, NULL) == -1)
			log_err("unveil: %s", strerror(errno));
	}

	if (pledge(cfg.quiet ? "stdio rpath wpath cpath" :
	    "stdio rpath wpath cpath proc exec", NULL) == -1) {
		log_err("pledge: %s", strerror(errno));
		capture_close_all(ifaces, nifaces);
		db_free();
		return 1;
	}
#endif

	while (!quit) {
		int ret = poll(pfds, nifaces, POLL_TIMEOUT_MS);

		if (ret < 0) {
			if (errno == EINTR)
				goto check_signals;
			log_err("poll: %s", strerror(errno));
			break;
		}

		for (int i = 0; i < nifaces; i++) {
			if (pfds[i].fd < 0)
				continue;

			if (pfds[i].revents & (POLLHUP | POLLERR)) {
				log_msg("interface %s down, disabling",
				        ifaces[i].name);
				pcap_close(ifaces[i].handle);
				ifaces[i].handle = NULL;
				ifaces[i].fd = -1;
				pfds[i].fd = -1;
				continue;
			}

			if (pfds[i].revents & POLLIN) {
				pcap_dispatch(ifaces[i].handle, -1,
				              parse_packet,
				              (u_char *)ifaces[i].name);
			}
		}

check_signals:
		if (save) {
			save = 0;
			db_save(cfg.dbfile);
		}
	}

	log_msg("shutting down");
	db_save(cfg.dbfile);
	capture_close_all(ifaces, nifaces);
	db_free();

	return 0;
}
