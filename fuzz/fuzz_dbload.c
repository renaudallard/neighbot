/*
 * Fuzz target for db_load().
 * Feeds arbitrary CSV data through the database loader.
 *
 * Build: make fuzz_dbload (from project root)
 * Run:   ./fuzz_dbload [-max_total_time=60]
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "../neighbot.h"
#include "../db.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

#define FUZZ_TMP "/tmp/fuzz_dbload.tmp"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FILE *fp;

	fp = fopen(FUZZ_TMP, "w");
	if (!fp)
		return 0;
	fwrite(data, 1, size, fp);
	fclose(fp);

	db_init();
	db_load(FUZZ_TMP);
	db_free();

	unlink(FUZZ_TMP);
	return 0;
}
