/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fortress policy blob format (v1) and its validating parser.
 *
 * This header and policy_parse.c are deliberately free of kernel
 * dependencies so the exact same parser is compiled into the kernel and
 * into host-side unit tests / fuzzers (tools/fortress-policy).
 *
 * All multi-byte fields are little-endian. All section offsets are
 * 4-byte aligned and relative to the start of the blob.
 *
 *   header        64 bytes
 *   apps[]        n_apps     x 12 bytes  { appid, flags, profile_id }
 *   tunnels[]     n_tunnels  x 32 bytes  { ifname[16], kind[16] }
 *   exempt[]      n_exempt   x 20 bytes  { appid, ifprefix[16] }
 *   profiles[]    n_profiles x  8 bytes  { offset, length }
 *   profile data  opaque bytes referenced by profiles[]
 */
#ifndef _SECURITY_FORTRESS_POLICY_PARSE_H
#define _SECURITY_FORTRESS_POLICY_PARSE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#endif

#define FPOL_MAGIC		"FRTP"
#define FPOL_VERSION		1
#define FPOL_HEADER_SIZE	64

#define FPOL_APP_ENTRY_SIZE	12
#define FPOL_TUNNEL_ENTRY_SIZE	32
#define FPOL_EXEMPT_ENTRY_SIZE	20
#define FPOL_PROFILE_ENTRY_SIZE	8

#define FPOL_NAME_LEN		16	/* == IFNAMSIZ */

/* Hard limits; anything larger is rejected. */
#define FPOL_MAX_SIZE		(4u << 20)
#define FPOL_MAX_APPS		10000u
#define FPOL_MAX_TUNNELS	8u
#define FPOL_MAX_EXEMPT		64u
#define FPOL_MAX_PROFILES	10000u
#define FPOL_MAX_PROFILE_LEN	(64u << 10)

/* Global policy flags. */
#define FPOL_F_ALLOW_FORWARD	(1u << 0)	/* permit forwarding out of non-tunnel ifaces */
#define FPOL_F_ALL		(FPOL_F_ALLOW_FORWARD)

/* Per-app flags. */
#define FPOL_APP_NET		(1u << 0)	/* may use the network (tunnel only) */
#define FPOL_APP_TRUSTED	(1u << 1)	/* platform component: IPC exemptions */
#define FPOL_APP_ALL		(FPOL_APP_NET | FPOL_APP_TRUSTED)

#define FPOL_PROFILE_NONE	0xffffffffu

/* Android AID ranges (per-user appid = uid % FPOL_PER_USER_RANGE). */
#define FPOL_PER_USER_RANGE	100000u
#define FPOL_APP_START		10000u
#define FPOL_APP_END		19999u
#define FPOL_SANDBOX_START	20000u
#define FPOL_SANDBOX_END	29999u
#define FPOL_ISOLATED_START	90000u
#define FPOL_ISOLATED_END	99999u

enum fpol_err {
	FPOL_OK = 0,
	FPOL_E_SIZE,		/* blob too small / too large / size mismatch */
	FPOL_E_MAGIC,
	FPOL_E_VERSION,
	FPOL_E_FLAGS,		/* unknown global or per-app flag bits */
	FPOL_E_COUNT,		/* a section count exceeds its limit */
	FPOL_E_BOUNDS,		/* a section or profile lies outside the blob */
	FPOL_E_ALIGN,
	FPOL_E_ORDER,		/* apps not strictly ascending by appid */
	FPOL_E_APPID,		/* appid outside the range allowed for the section */
	FPOL_E_PROFILE,		/* dangling profile_id or oversized profile */
	FPOL_E_NAME,		/* bad interface name / kind */
	FPOL_E_RESERVED,	/* reserved header bytes not zero */
};

struct fpol_app {
	u32 appid;
	u32 flags;
	u32 profile_id;
};

/* Validated, zero-copy view over a policy blob. */
struct fpol_view {
	const u8 *base;
	u32 size;
	u32 flags;
	u32 serial;
	u32 n_apps, apps_off;
	u32 n_tunnels, tunnels_off;
	u32 n_exempt, exempt_off;
	u32 n_profiles, profiles_off;
};

/* Classification of a uid by its appid. */
enum fpol_uid_class {
	FPOL_CLASS_SYSTEM = 0,	/* appid < 10000 and other non-app ranges */
	FPOL_CLASS_APP,		/* regular installed app */
	FPOL_CLASS_SANDBOX,	/* SDK sandbox process */
	FPOL_CLASS_ISOLATED,	/* isolated / app-zygote process */
};

enum fpol_uid_class fpol_classify_appid(u32 appid);

static inline u32 fpol_appid(u32 uid)
{
	return uid % FPOL_PER_USER_RANGE;
}

/* Validate @buf and fill @view. Returns an enum fpol_err value. */
int fpol_parse(const u8 *buf, size_t len, struct fpol_view *view);

const char *fpol_strerror(int err);

/* Lookups on a validated view. All return 0 when not found. */
int fpol_find_app(const struct fpol_view *v, u32 appid, struct fpol_app *out);
int fpol_tunnel_match(const struct fpol_view *v, const char *ifname,
		      const char *kind);
int fpol_exempt_match(const struct fpol_view *v, u32 appid,
		      const char *ifname);
int fpol_profile(const struct fpol_view *v, u32 profile_id,
		 const u8 **data, u32 *len);

#endif /* _SECURITY_FORTRESS_POLICY_PARSE_H */
