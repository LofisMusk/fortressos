/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Identity Guard path rules.
 *
 * Like policy_parse.[ch], this is free of kernel dependencies, so the very
 * same rule tables and matcher are compiled into the kernel and into the
 * host tests (tools/fortress-policy).
 */
#ifndef _SECURITY_FORTRESS_IDPATH_H
#define _SECURITY_FORTRESS_IDPATH_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
#endif

/* The filesystems the Identity Guard has rules for. */
enum fid_fs {
	FID_FS_PROC,
	FID_FS_SYS,
};

/*
 * True if @path must not be opened by an untrusted uid because it carries
 * hardware, network or cross-app identity.
 *
 * @path is the path of the file *within* @fs, as dentry_path_raw() produces
 * it: "/1234/net/arp" for /proc/self/net/arp. Matching inside the
 * filesystem rather than against a mount path means a second mount of
 * procfs, or a bind mount of a subdirectory, changes nothing.
 */
bool fid_path_denied(enum fid_fs fs, const char *path);

/*
 * The glob matcher behind the rules, exposed for the host tests. A "*"
 * pattern segment matches exactly one path segment, "**" matches any
 * number of segments including none.
 */
bool fid_path_match(const char *pat, const char *path);

#endif /* _SECURITY_FORTRESS_IDPATH_H */
