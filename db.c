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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "neighbot.h"
#include "db.h"
#include "log.h"

static struct entry *buckets[HT_BUCKETS];
static unsigned     entry_count;
static int          limit_warned;

static uint32_t
fnv1a(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint32_t h = 2166136261u;

	for (size_t i = 0; i < len; i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	return h;
}

static unsigned
hash_key(int af, const uint8_t *ip)
{
	uint8_t buf[17];
	size_t len;

	buf[0] = (uint8_t)af;
	len = (af == AF_INET) ? 4 : 16;
	memcpy(buf + 1, ip, len);
	return fnv1a(buf, 1 + len) % HT_BUCKETS;
}

static int
ip_len(int af)
{
	return (af == AF_INET) ? 4 : 16;
}

void
db_init(void)
{
	memset(buckets, 0, sizeof(buckets));
}

int
db_load(const char *path)
{
	FILE *fp;
	char line[512];
	int count = 0;

	fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT)
			return 0;
		log_err("db_load: %s: %s", path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char ipstr[INET6_ADDRSTRLEN];
		char macstr[18];
		char iface[32];
		char first_str[32], last_str[32];
		struct entry *e;
		unsigned idx;

		/* strip newline */
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '\0' || line[0] == '#')
			continue;

		if (sscanf(line, "%45[^,],%17[^,],%31[^,],%31[^,],%31s",
		           ipstr, macstr, iface, first_str, last_str) != 5)
			continue;

		e = calloc(1, sizeof(*e));
		if (!e) {
			log_err("db_load: out of memory");
			fclose(fp);
			return -1;
		}

		if (inet_pton(AF_INET, ipstr, e->ip) == 1) {
			e->af = AF_INET;
		} else if (inet_pton(AF_INET6, ipstr, e->ip) == 1) {
			e->af = AF_INET6;
		} else {
			free(e);
			continue;
		}

		/* parse MAC */
		unsigned m[6];
		if (sscanf(macstr, "%x:%x:%x:%x:%x:%x",
		           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
			free(e);
			continue;
		}
		for (int i = 0; i < 6; i++)
			e->mac[i] = (uint8_t)m[i];

		snprintf(e->iface, sizeof(e->iface), "%s", iface);

		/* parse timestamps */
		struct tm tm;
		memset(&tm, 0, sizeof(tm));
		tm.tm_isdst = -1;
		if (strptime(first_str, "%Y-%m-%dT%H:%M:%S", &tm))
			e->first_seen = mktime(&tm);
		memset(&tm, 0, sizeof(tm));
		tm.tm_isdst = -1;
		if (strptime(last_str, "%Y-%m-%dT%H:%M:%S", &tm))
			e->last_seen = mktime(&tm);

		idx = hash_key(e->af, e->ip);
		e->next = buckets[idx];
		buckets[idx] = e;
		entry_count++;
		count++;
	}

	fclose(fp);
	log_msg("loaded %d entries from %s", count, path);
	return count;
}

int
db_save(const char *path)
{
	char tmp[PATH_MAX];
	FILE *fp;
	int fd, count = 0;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	/* remove stale temp file, then create exclusively to prevent
	 * symlink attacks (O_NOFOLLOW + O_EXCL) with fixed permissions */
	(void)unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
	if (fd < 0) {
		log_err("db_save: %s: %s", tmp, strerror(errno));
		return -1;
	}
	fp = fdopen(fd, "w");
	if (!fp) {
		log_err("db_save: fdopen: %s", strerror(errno));
		close(fd);
		unlink(tmp);
		return -1;
	}

	for (unsigned i = 0; i < HT_BUCKETS; i++) {
		for (struct entry *e = buckets[i]; e; e = e->next) {
			char ipstr[INET6_ADDRSTRLEN];
			char first_str[32], last_str[32];
			struct tm tm;

			inet_ntop(e->af, e->ip, ipstr, sizeof(ipstr));

			localtime_r(&e->first_seen, &tm);
			strftime(first_str, sizeof(first_str),
			         "%Y-%m-%dT%H:%M:%S", &tm);
			localtime_r(&e->last_seen, &tm);
			strftime(last_str, sizeof(last_str),
			         "%Y-%m-%dT%H:%M:%S", &tm);

			fprintf(fp, "%s,%02x:%02x:%02x:%02x:%02x:%02x,%s,%s,%s\n",
			        ipstr,
			        e->mac[0], e->mac[1], e->mac[2],
			        e->mac[3], e->mac[4], e->mac[5],
			        e->iface, first_str, last_str);
			count++;
		}
	}

	if (fclose(fp) != 0) {
		log_err("db_save: fclose: %s", strerror(errno));
		unlink(tmp);
		return -1;
	}

	if (rename(tmp, path) != 0) {
		log_err("db_save: rename: %s", strerror(errno));
		unlink(tmp);
		return -1;
	}

	log_msg("saved %d entries to %s", count, path);
	return count;
}

/* Returns EVENT_NEW, EVENT_CHANGED, or 0 (no change).
 * If EVENT_CHANGED, old_mac is filled with the previous MAC. */
int
db_update(int af, const uint8_t *ip, const uint8_t *mac,
          const char *iface, uint8_t *old_mac)
{
	unsigned idx = hash_key(af, ip);
	int ilen = ip_len(af);
	time_t now = time(NULL);

	for (struct entry *e = buckets[idx]; e; e = e->next) {
		if (e->af == af && memcmp(e->ip, ip, ilen) == 0) {
			e->last_seen = now;
			if (memcmp(e->mac, mac, 6) != 0) {
				if (old_mac)
					memcpy(old_mac, e->mac, 6);
				memcpy(e->mac, mac, 6);
				snprintf(e->iface, sizeof(e->iface), "%s", iface);
				return EVENT_CHANGED;
			}
			return 0;
		}
	}

	/* new entry */
	if (entry_count >= MAX_ENTRIES) {
		if (!limit_warned) {
			log_err("db_update: entry limit reached (%u)",
			    MAX_ENTRIES);
			limit_warned = 1;
		}
		return 0;
	}

	struct entry *e = calloc(1, sizeof(*e));
	if (!e) {
		log_err("db_update: out of memory");
		return 0;
	}

	e->af = af;
	memcpy(e->ip, ip, ilen);
	memcpy(e->mac, mac, 6);
	snprintf(e->iface, sizeof(e->iface), "%s", iface);
	e->first_seen = now;
	e->last_seen = now;
	e->next = buckets[idx];
	buckets[idx] = e;
	entry_count++;
	return EVENT_NEW;
}

void
db_free(void)
{
	for (unsigned i = 0; i < HT_BUCKETS; i++) {
		struct entry *e = buckets[i];
		while (e) {
			struct entry *next = e->next;
			free(e);
			e = next;
		}
		buckets[i] = NULL;
	}
	entry_count = 0;
	limit_warned = 0;
}
