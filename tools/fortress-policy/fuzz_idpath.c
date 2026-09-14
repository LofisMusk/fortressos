// SPDX-License-Identifier: GPL-2.0
/*
 * libFuzzer target for the Identity Guard path matcher. The matcher
 * backtracks, so this looks for both out-of-bounds reads and inputs that
 * fail to terminate (-timeout catches those).
 */
#include <stdlib.h>
#include <string.h>

#include "idpath.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	/* NUL-terminated exact-size copy, so ASan flags any read past it. */
	char *path = malloc(size + 1);

	memcpy(path, data, size);
	path[size] = '\0';

	fid_path_denied(FID_FS_PROC, path);
	fid_path_denied(FID_FS_SYS, path);

	/* The path doubles as a pattern: exercise "*"/"**" handling too. */
	fid_path_match(path, "/devices/platform/soc/net/wlan0/address");
	fid_path_match("/**/*/**", path);

	free(path);
	return 0;
}
