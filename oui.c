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

		/* neighbot format: aa:bb:cc Vendor Name */
		if (sscanf(line, "%x:%x:%x %79[^\n]",
		           &a, &b, &c, vendor) != 4) {
			/* arp-scan format: AABBCC\tVendor Name
			 * skip MA-M (7 hex) and MA-S (9 hex) entries */
			unsigned oui;
			int pos;

			if (sscanf(line, "%6x%n", &oui, &pos) != 1 ||
			    pos != 6 || line[6] != '\t')
				continue;
			a = (oui >> 16) & 0xff;
			b = (oui >> 8) & 0xff;
			c = oui & 0xff;
			line[strcspn(line, "\n")] = '\0';
			snprintf(vendor, sizeof(vendor), "%.79s", line + 7);
			if (vendor[0] == '\0')
				continue;
		}

		if (oui_count >= oui_alloc) {
			int new_alloc = oui_alloc ? oui_alloc * 2 : 1024;
			if (new_alloc <= oui_alloc) {
				/* int overflow */
				fclose(fp);
				return oui_count;
			}
			struct oui_entry *tmp = realloc(oui_db,
			    (size_t)new_alloc * sizeof(*tmp));
			if (!tmp) {
				fclose(fp);
				return oui_count;
			}
			oui_db = tmp;
			oui_alloc = new_alloc;
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
