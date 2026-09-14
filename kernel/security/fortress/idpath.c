// SPDX-License-Identifier: GPL-2.0
/*
 * Identity Guard path rules and their matcher. Shared verbatim between the
 * kernel and host-side tests, so it must not depend on anything but
 * idpath.h.
 *
 * What a virtual identity should *say* is policy, and lives in the policy
 * blob. What an app must never see at all is not negotiable, so these
 * rules are compiled in: they hold in the UNLOADED state too.
 */
#include "idpath.h"

/* Split off the leading segment of @s; returns what is left of @s. */
static const char *next_seg(const char *s, const char **seg, unsigned int *len)
{
	const char *start;

	while (*s == '/')
		s++;
	start = s;
	while (*s && *s != '/')
		s++;
	*seg = start;
	*len = (unsigned int)(s - start);
	return s;
}

static bool seg_eq(const char *a, const char *b, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/*
 * Segment-wise glob match with a single backtracking point, the usual
 * linear algorithm: on a mismatch the last "**" swallows one more path
 * segment and matching restarts after it.
 */
bool fid_path_match(const char *pat, const char *path)
{
	const char *bt_pat = NULL, *bt_path = NULL;

	for (;;) {
		const char *pseg, *sseg, *pnext, *snext;
		unsigned int plen, slen;

		pnext = next_seg(pat, &pseg, &plen);
		if (plen == 2 && pseg[0] == '*' && pseg[1] == '*') {
			bt_pat = pnext;
			bt_path = path;
			pat = pnext;
			continue;
		}

		snext = next_seg(path, &sseg, &slen);
		if (!plen && !slen)
			return true;		/* both exhausted */

		if (plen && slen &&
		    ((plen == 1 && pseg[0] == '*') ||
		     (plen == slen && seg_eq(pseg, sseg, slen)))) {
			pat = pnext;
			path = snext;
			continue;
		}

		if (!bt_pat)
			return false;
		bt_path = next_seg(bt_path, &sseg, &slen);
		if (!slen)
			return false;		/* nothing left to swallow */
		pat = bt_pat;
		path = bt_path;
	}
}

/*
 * /proc/net is a symlink to self/net, so the path of /proc/net/arp really
 * is "/<pid>/net/arp"; both spellings are listed because the symlink is
 * not guaranteed. The whole tree is network-namespace wide, not per
 * process: /proc/net/tcp and /proc/net/unix enumerate every app's sockets,
 * /proc/net/arp the LAN neighbours (a precise location fingerprint),
 * /proc/net/dev the interfaces, including the tunnel, and their counters.
 */
static const char *const proc_denied[] = {
	"/net/**",
	"/*/net/**",
	"/cpuinfo",			/* Qualcomm prints "Serial" here */
	"/sys/kernel/random/boot_id",	/* a stable id shared by all apps */
};

/*
 * /sys/class/X/Y is a symlink into /sys/devices, and open() resolves it,
 * so every class rule needs its /sys/devices counterpart. The class
 * directories themselves stay listed: opening one is how an app
 * enumerates interfaces without touching a single leaf file.
 */
static const char *const sys_denied[] = {
	"/class/net/**",
	"/class/bluetooth/**",
	"/devices/**/net/**",
	"/devices/**/bluetooth/**",
	"/devices/**/mmc_host/**",	/* eMMC CID, serial, manufacturer */
	"/devices/**/android_usb/**",	/* iSerial is the device serial */
	"/devices/soc0/**",		/* SoC serial, machine, revision */
	"/firmware/devicetree/**",	/* serial-number, board ids */
	/* Catch-alls, for wherever a vendor driver exposes an identifier. */
	"/**/address",
	"/**/cid",
	"/**/serial",
	"/**/serial_number",
	"/**/unique_id",
};

bool fid_path_denied(enum fid_fs fs, const char *path)
{
	const char *const *rules;
	unsigned int n, i;

	switch (fs) {
	case FID_FS_PROC:
		rules = proc_denied;
		n = sizeof(proc_denied) / sizeof(proc_denied[0]);
		break;
	case FID_FS_SYS:
		rules = sys_denied;
		n = sizeof(sys_denied) / sizeof(sys_denied[0]);
		break;
	default:
		return true;		/* unknown filesystem: fail closed */
	}

	for (i = 0; i < n; i++)
		if (fid_path_match(rules[i], path))
			return true;
	return false;
}
