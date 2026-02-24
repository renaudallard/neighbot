/*
 * Fuzz target for oui_load().
 * Feeds arbitrary OUI file data through the vendor database loader.
 *
 * Build: make fuzz_ouiload (from project root)
 * Run:   ./fuzz_ouiload [-max_total_time=60]
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "../neighbot.h"
#include "../oui.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

#define FUZZ_TMP "/tmp/fuzz_ouiload.tmp"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FILE *fp;

	fp = fopen(FUZZ_TMP, "w");
	if (!fp)
		return 0;
	fwrite(data, 1, size, fp);
	fclose(fp);

	oui_load(FUZZ_TMP);
	oui_free();

	unlink(FUZZ_TMP);
	return 0;
}
