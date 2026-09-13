// SPDX-License-Identifier: GPL-2.0
/* libFuzzer target for the kernel policy parser. */
#include <stdlib.h>
#include <string.h>

#include "policy_parse.h"

int LLVMFuzzerTestOneInput(const u8 *data, size_t size)
{
	struct fpol_view v;
	const u8 *d;
	u32 l, i;
	u8 *copy;

	/* Exact-size heap copy so ASan flags any read past the end. */
	copy = malloc(size ? size : 1);
	memcpy(copy, data, size);

	if (fpol_parse(copy, size, &v) == FPOL_OK) {
		for (i = 0; i < v.n_profiles; i++) {
			if (fpol_profile(&v, i, &d, &l) && l)
				(void)d[l - 1];
		}
		for (i = 0; i < 64; i++)
			fpol_find_app(&v, 10000 + i, NULL);
		fpol_tunnel_match(&v, "fwg0", "wireguard");
		fpol_exempt_match(&v, 1073, "wlan0");
	}
	free(copy);
	return 0;
}
