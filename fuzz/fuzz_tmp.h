/*
 * Shared by the file loader fuzz targets, which feed each input to the
 * loader through a file. The file is made once per process by mkstemp()
 * in $TMPDIR (default /tmp), so parallel runs (-jobs, -fork) and other
 * users of the directory never share it, and is removed at exit.
 */

#ifndef FUZZ_TMP_H
#define FUZZ_TMP_H

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static char fuzz_tmp_path[PATH_MAX];

static void
fuzz_tmp_remove(void)
{
	unlink(fuzz_tmp_path);
}

/* Write data to the file of this process and return its path. */
static const char *
fuzz_tmp_write(const char *name, const uint8_t *data, size_t size)
{
	static int fd = -1;

	if (fd < 0) {
		const char *dir = getenv("TMPDIR");

		snprintf(fuzz_tmp_path, sizeof(fuzz_tmp_path), "%s/%s.XXXXXX",
		    dir != NULL && *dir != '\0' ? dir : "/tmp", name);
		fd = mkstemp(fuzz_tmp_path);
		if (fd < 0) {
			perror("mkstemp");
			abort();
		}
		atexit(fuzz_tmp_remove);
	}
	if (ftruncate(fd, 0) < 0 ||
	    pwrite(fd, data, size, 0) != (ssize_t)size) {
		perror(fuzz_tmp_path);
		abort();
	}
	return fuzz_tmp_path;
}

#endif
