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

#ifndef NEIGHBOT_H
#define NEIGHBOT_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#define NEIGHBOT_VERSION "0.1.2"

#define DEFAULT_DBFILE  "/var/neighbot/neighbot.csv"
#define DEFAULT_MAILTO  "root"
#define DEFAULT_USER    "nobody"
#define DEFAULT_OUIFILE "/usr/local/share/neighbot/oui.txt"

#define HT_BUCKETS      1024
#define MAX_ENTRIES      100000
#define MAX_IFACES       64
#define SNAP_LEN         128
#define POLL_TIMEOUT_MS  1000

#define BPF_FILTER "arp or (icmp6 and (ip6[40] == 136 or ip6[40] == 135))"

struct config {
	int    daemonize;
	int    quiet;
	char  *dbfile;
	char  *mailto;
	char  *user;
};

extern struct config cfg;
extern volatile sig_atomic_t quit;
extern volatile sig_atomic_t save;

#endif
