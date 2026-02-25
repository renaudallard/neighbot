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

#ifndef NEIGHBOT_H
#define NEIGHBOT_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#define NEIGHBOT_VERSION "0.3.6"

#define DEFAULT_DBFILE  "/var/neighbot/neighbot.csv"
#define DEFAULT_MAILTO  "root"
#define DEFAULT_USER    "nobody"
#define DEFAULT_OUIFILE  "/var/neighbot/oui.txt"
#define DEFAULT_SENDMAIL "/usr/sbin/sendmail"

#define HT_BUCKETS      1024
#define MAX_ENTRIES      100000
#define MAX_IFACES       64
#define SNAP_LEN         128
#define POLL_TIMEOUT_MS  1000
#define MAX_SUBNETS      256
#define REAPPEAR_SECS    (180 * 24 * 3600)  /* 6 months */

#define BPF_FILTER "arp or (icmp6 and (ip6[40] == 136 or ip6[40] == 135))"

struct config {
	int    daemonize;
	int    quiet;
	int    probe;
	char  *dbfile;
	char  *iface;
	char  *mailto;
	char  *ouifile;
	char  *sendmail;
	char  *user;
};

extern struct config cfg;
extern volatile sig_atomic_t quit;
extern volatile sig_atomic_t save;

#endif
