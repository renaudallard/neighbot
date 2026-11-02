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
#include "fuzz_tmp.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *path = fuzz_tmp_write("fuzz_dbload", data, size);

	db_init();
	db_load(path);
	db_free();
	return 0;
}
