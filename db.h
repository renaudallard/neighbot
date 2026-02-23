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

#ifndef DB_H
#define DB_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

#define EVENT_NEW     1
#define EVENT_CHANGED 2

struct entry {
	int            af;        /* AF_INET or AF_INET6 */
	uint8_t        ip[16];    /* network byte order */
	uint8_t        mac[6];
	char           iface[32];
	time_t         first_seen;
	time_t         last_seen;
	struct entry  *next;
};

void  db_init(void);
int   db_load(const char *path);
int   db_save(const char *path);
int   db_update(int af, const uint8_t *ip, const uint8_t *mac,
                const char *iface, uint8_t *old_mac);
void  db_free(void);

#endif
