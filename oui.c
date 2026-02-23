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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oui.h"
#include "log.h"

#define VENDOR_MAX 80

struct oui_entry {
	uint8_t prefix[3];
	char    vendor[VENDOR_MAX];
};

static struct oui_entry *oui_db;
static int oui_count;
static int oui_alloc;

static int
oui_cmp(const void *a, const void *b)
{
	return memcmp(((const struct oui_entry *)a)->prefix,
	              ((const struct oui_entry *)b)->prefix, 3);
}

int
oui_load(const char *path)
{
	FILE *fp;
	char line[256];

	fp = fopen(path, "r");
	if (!fp)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		unsigned a, b, c;
		char vendor[VENDOR_MAX];

		if (sscanf(line, "%x:%x:%x %79[^\n]",
		           &a, &b, &c, vendor) != 4)
			continue;

		if (oui_count >= oui_alloc) {
			oui_alloc = oui_alloc ? oui_alloc * 2 : 1024;
			struct oui_entry *tmp = realloc(oui_db,
			    oui_alloc * sizeof(*tmp));
			if (!tmp) {
				fclose(fp);
				return oui_count;
			}
			oui_db = tmp;
		}

		oui_db[oui_count].prefix[0] = (uint8_t)a;
		oui_db[oui_count].prefix[1] = (uint8_t)b;
		oui_db[oui_count].prefix[2] = (uint8_t)c;
		snprintf(oui_db[oui_count].vendor, VENDOR_MAX, "%s", vendor);
		oui_count++;
	}

	fclose(fp);

	if (oui_count > 0)
		qsort(oui_db, oui_count, sizeof(*oui_db), oui_cmp);

	log_msg("loaded %d OUI entries from %s", oui_count, path);
	return oui_count;
}

const char *
oui_lookup(const uint8_t *mac)
{
	struct oui_entry key;
	struct oui_entry *found;

	if (oui_count == 0)
		return NULL;

	memcpy(key.prefix, mac, 3);
	found = bsearch(&key, oui_db, oui_count, sizeof(*oui_db), oui_cmp);
	return found ? found->vendor : NULL;
}

void
oui_free(void)
{
	free(oui_db);
	oui_db = NULL;
	oui_count = 0;
	oui_alloc = 0;
}
