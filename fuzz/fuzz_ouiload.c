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
#include "fuzz_tmp.h"

/* globals required by the linker */
struct config          cfg;
volatile sig_atomic_t  quit;
volatile sig_atomic_t  save;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	oui_load(fuzz_tmp_write("fuzz_ouiload", data, size));
	oui_free();
	return 0;
}
