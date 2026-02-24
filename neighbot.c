/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/stat.h>

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
#include "oui.h"
#include "parse.h"
#include "probe.h"

struct config cfg = {
	.daemonize = 0,
	.quiet     = 0,
	.probe     = 1,
	.dbfile    = NULL,
	.iface     = NULL,
	.mailto    = NULL,
	.sendmail  = NULL,
	.user      = NULL,
};

volatile sig_atomic_t quit;
volatile sig_atomic_t save;
static volatile sig_atomic_t dump_probes;

static void
sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		quit = 1;
	else if (sig == SIGHUP)
		save = 1;
	else if (sig == SIGUSR1)
		dump_probes = 1;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: neighbot [-d] [-f dbfile] [-i iface] [-m mailto] "
	    "[-o ouifile] [-p] [-q] [-s sendmail] [-u user]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct iface ifaces[MAX_IFACES];
	struct pollfd pfds[MAX_IFACES];
	int nifaces, ch;

	cfg.dbfile   = DEFAULT_DBFILE;
	cfg.mailto   = DEFAULT_MAILTO;
	cfg.ouifile  = DEFAULT_OUIFILE;
	cfg.sendmail = DEFAULT_SENDMAIL;
	cfg.user     = DEFAULT_USER;

	while ((ch = getopt(argc, argv, "df:i:m:o:pqs:u:")) != -1) {
		switch (ch) {
		case 'd':
			cfg.daemonize = 1;
			break;
		case 'f':
			cfg.dbfile = optarg;
			break;
		case 'i':
			cfg.iface = optarg;
			break;
		case 'm':
			cfg.mailto = optarg;
			break;
		case 'o':
			cfg.ouifile = optarg;
			break;
		case 'p':
			cfg.probe = 0;
			break;
		case 'q':
			cfg.quiet = 1;
			break;
		case 's':
			cfg.sendmail = optarg;
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
	sigaction(SIGUSR1, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	db_init();
	db_load(cfg.dbfile);
	oui_load(cfg.ouifile);

	nifaces = capture_open_all(ifaces, MAX_IFACES);
	if (nifaces <= 0) {
		log_err("no usable interfaces found");
		db_free();
		oui_free();
		return 1;
	}

	if (cfg.daemonize) {
		if (daemon(1, 0) < 0) {
			log_err("daemon: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			oui_free();
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
			oui_free();
			return 1;
		}

		/* fix ownership and permissions on DB directory and file */
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
		if (chmod(dbdir, 0750) < 0)
			log_err("chmod %s: %s", dbdir, strerror(errno));
		(void)chown(cfg.dbfile, pw->pw_uid, pw->pw_gid);
		(void)chmod(cfg.dbfile, 0640);

		if (setgroups(1, &pw->pw_gid) < 0) {
			log_err("setgroups: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			oui_free();
			return 1;
		}
		if (setgid(pw->pw_gid) < 0) {
			log_err("setgid: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			oui_free();
			return 1;
		}
		if (setuid(pw->pw_uid) < 0) {
			log_err("setuid: %s", strerror(errno));
			capture_close_all(ifaces, nifaces);
			db_free();
			oui_free();
			return 1;
		}

		log_msg("dropped privileges to %s", cfg.user);
	}

	log_msg("neighbot %s started, monitoring %d interface(s)",
	        NEIGHBOT_VERSION, nifaces);
	log_msg("active probing %s", cfg.probe ? "enabled" : "disabled");

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
	    "stdio rpath wpath cpath proc exec dns", NULL) == -1) {
		log_err("pledge: %s", strerror(errno));
		capture_close_all(ifaces, nifaces);
		db_free();
		oui_free();
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
		if (cfg.probe)
			probe_tick(ifaces, nifaces);
		if (dump_probes) {
			dump_probes = 0;
			probe_dump();
		}
		if (save) {
			save = 0;
			db_save(cfg.dbfile);
		}
	}

	log_msg("shutting down");
	db_save(cfg.dbfile);
	capture_close_all(ifaces, nifaces);
	db_free();
	oui_free();

	return 0;
}
