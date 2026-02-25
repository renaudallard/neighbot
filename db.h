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

#ifndef DB_H
#define DB_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

#define EVENT_NEW        1
#define EVENT_CHANGED    2
#define EVENT_MOVED      3
#define EVENT_FLIPFLOP   4
#define EVENT_REAPPEARED 5

struct entry {
	int            af;        /* AF_INET or AF_INET6 */
	uint8_t        ip[16];    /* network byte order */
	uint8_t        mac[6];
	uint8_t        prev_mac[6];
	char           iface[32];
	time_t         first_seen;
	time_t         last_seen;
	struct entry  *next;
};

struct db_entry_info {
	int      af;
	uint8_t  ip[16];
	char     iface[32];
};

void  format_mac(const uint8_t *mac, char *buf, size_t len);
void  db_init(void);
int   db_load(const char *path);
int   db_save(const char *path);
int   db_update(int af, const uint8_t *ip, const uint8_t *mac,
                const char *iface, uint8_t *old_mac,
                time_t *old_last_seen);
void  db_free(void);
int   db_other_ips(const uint8_t *mac, int exclude_af,
                   const uint8_t *exclude_ip, char *buf, size_t len);
int   db_find_other_entries(const uint8_t *mac, int exclude_af,
                            const uint8_t *exclude_ip,
                            struct db_entry_info *out, int max);
int   db_has_temp_in_prefix(const uint8_t *mac, const uint8_t *ip6);

/* Check if IPv6 address uses EUI-64 interface ID derived from MAC. */
static inline int
is_eui64(const uint8_t *ip6, const uint8_t *mac)
{
	return ip6[8]  == (mac[0] ^ 0x02) &&
	       ip6[9]  == mac[1] &&
	       ip6[10] == mac[2] &&
	       ip6[11] == 0xff &&
	       ip6[12] == 0xfe &&
	       ip6[13] == mac[3] &&
	       ip6[14] == mac[4] &&
	       ip6[15] == mac[5];
}

#endif
