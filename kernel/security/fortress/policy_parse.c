// SPDX-License-Identifier: GPL-2.0
/*
 * Fortress policy blob parser. Shared verbatim between the kernel and
 * host-side tests, so it must not depend on anything but policy_parse.h.
 *
 * The parser is the only code that touches untrusted bytes; everything is
 * bounds-checked with 64-bit arithmetic before any access, and a blob is
 * either accepted as a whole or rejected as a whole.
 */
#include "policy_parse.h"

typedef unsigned long long fpol_u64;

static u32 get_le16(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8);
}

static u32 get_le32(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) |
	       ((u32)p[3] << 24);
}

enum fpol_uid_class fpol_classify_appid(u32 appid)
{
	if (appid >= FPOL_APP_START && appid <= FPOL_APP_END)
		return FPOL_CLASS_APP;
	if (appid >= FPOL_SANDBOX_START && appid <= FPOL_SANDBOX_END)
		return FPOL_CLASS_SANDBOX;
	if (appid >= FPOL_ISOLATED_START && appid <= FPOL_ISOLATED_END)
		return FPOL_CLASS_ISOLATED;
	return FPOL_CLASS_SYSTEM;
}

const char *fpol_strerror(int err)
{
	switch (err) {
	case FPOL_OK:		return "ok";
	case FPOL_E_SIZE:	return "bad size";
	case FPOL_E_MAGIC:	return "bad magic";
	case FPOL_E_VERSION:	return "unsupported version";
	case FPOL_E_FLAGS:	return "unknown flags";
	case FPOL_E_COUNT:	return "count over limit";
	case FPOL_E_BOUNDS:	return "section out of bounds";
	case FPOL_E_ALIGN:	return "misaligned section";
	case FPOL_E_ORDER:	return "apps not sorted/unique";
	case FPOL_E_APPID:	return "appid out of range";
	case FPOL_E_PROFILE:	return "bad profile";
	case FPOL_E_NAME:	return "bad interface name";
	case FPOL_E_RESERVED:	return "reserved bytes not zero";
	}
	return "unknown error";
}

/*
 * A name field is FPOL_NAME_LEN bytes: 1..15 bytes of [0x21-0x7e] except
 * '/' and ':' (mirrors dev_valid_name()), then NUL padding to the end.
 */
static int valid_name(const u8 *p)
{
	u32 i, n = 0;

	while (n < FPOL_NAME_LEN && p[n])
		n++;
	if (n == 0 || n == FPOL_NAME_LEN)
		return 0;
	for (i = 0; i < n; i++) {
		if (p[i] < 0x21 || p[i] > 0x7e || p[i] == '/' || p[i] == ':')
			return 0;
	}
	for (i = n; i < FPOL_NAME_LEN; i++) {
		if (p[i])
			return 0;
	}
	return 1;
}

static int check_section(u32 size, u32 n, u32 off, u32 entsize, u32 max)
{
	if (n > max)
		return FPOL_E_COUNT;
	if (n == 0)
		return off == 0 ? FPOL_OK : FPOL_E_BOUNDS;
	if (off & 3)
		return FPOL_E_ALIGN;
	if (off < FPOL_HEADER_SIZE ||
	    (fpol_u64)off + (fpol_u64)n * entsize > size)
		return FPOL_E_BOUNDS;
	return FPOL_OK;
}

int fpol_parse(const u8 *buf, size_t len, struct fpol_view *v)
{
	const u8 *p;
	u32 i, prev = 0;
	int err;

	if (!buf || len < FPOL_HEADER_SIZE || len > FPOL_MAX_SIZE)
		return FPOL_E_SIZE;
	if (buf[0] != FPOL_MAGIC[0] || buf[1] != FPOL_MAGIC[1] ||
	    buf[2] != FPOL_MAGIC[2] || buf[3] != FPOL_MAGIC[3])
		return FPOL_E_MAGIC;
	if (get_le16(buf + 4) != FPOL_VERSION)
		return FPOL_E_VERSION;
	if (get_le16(buf + 6) != FPOL_HEADER_SIZE)
		return FPOL_E_SIZE;
	if (get_le32(buf + 8) != len)
		return FPOL_E_SIZE;
	for (i = 52; i < FPOL_HEADER_SIZE; i++) {
		if (buf[i])
			return FPOL_E_RESERVED;
	}

	v->base = buf;
	v->size = (u32)len;
	v->flags = get_le32(buf + 12);
	v->serial = get_le32(buf + 16);
	v->n_apps = get_le32(buf + 20);
	v->apps_off = get_le32(buf + 24);
	v->n_tunnels = get_le32(buf + 28);
	v->tunnels_off = get_le32(buf + 32);
	v->n_exempt = get_le32(buf + 36);
	v->exempt_off = get_le32(buf + 40);
	v->n_profiles = get_le32(buf + 44);
	v->profiles_off = get_le32(buf + 48);

	if (v->flags & ~FPOL_F_ALL)
		return FPOL_E_FLAGS;

	err = check_section(v->size, v->n_apps, v->apps_off,
			    FPOL_APP_ENTRY_SIZE, FPOL_MAX_APPS);
	if (err)
		return err;
	err = check_section(v->size, v->n_tunnels, v->tunnels_off,
			    FPOL_TUNNEL_ENTRY_SIZE, FPOL_MAX_TUNNELS);
	if (err)
		return err;
	err = check_section(v->size, v->n_exempt, v->exempt_off,
			    FPOL_EXEMPT_ENTRY_SIZE, FPOL_MAX_EXEMPT);
	if (err)
		return err;
	err = check_section(v->size, v->n_profiles, v->profiles_off,
			    FPOL_PROFILE_ENTRY_SIZE, FPOL_MAX_PROFILES);
	if (err)
		return err;

	for (i = 0; i < v->n_profiles; i++) {
		u32 off, plen;

		p = buf + v->profiles_off + i * FPOL_PROFILE_ENTRY_SIZE;
		off = get_le32(p);
		plen = get_le32(p + 4);
		if (plen > FPOL_MAX_PROFILE_LEN)
			return FPOL_E_PROFILE;
		if (off < FPOL_HEADER_SIZE ||
		    (fpol_u64)off + plen > v->size)
			return FPOL_E_BOUNDS;
	}

	for (i = 0; i < v->n_apps; i++) {
		u32 appid, flags, profile_id;

		p = buf + v->apps_off + i * FPOL_APP_ENTRY_SIZE;
		appid = get_le32(p);
		flags = get_le32(p + 4);
		profile_id = get_le32(p + 8);
		if (fpol_classify_appid(appid) != FPOL_CLASS_APP)
			return FPOL_E_APPID;
		if (i > 0 && appid <= prev)
			return FPOL_E_ORDER;
		if (flags & ~FPOL_APP_ALL)
			return FPOL_E_FLAGS;
		if (profile_id != FPOL_PROFILE_NONE &&
		    profile_id >= v->n_profiles)
			return FPOL_E_PROFILE;
		prev = appid;
	}

	for (i = 0; i < v->n_tunnels; i++) {
		p = buf + v->tunnels_off + i * FPOL_TUNNEL_ENTRY_SIZE;
		if (!valid_name(p) || !valid_name(p + FPOL_NAME_LEN))
			return FPOL_E_NAME;
	}

	/*
	 * Exemptions (physical-network access) may only name system uids:
	 * no installed app, sandbox or isolated process can ever be exempt.
	 */
	for (i = 0; i < v->n_exempt; i++) {
		p = buf + v->exempt_off + i * FPOL_EXEMPT_ENTRY_SIZE;
		if (fpol_classify_appid(get_le32(p)) != FPOL_CLASS_SYSTEM)
			return FPOL_E_APPID;
		if (!valid_name(p + 4))
			return FPOL_E_NAME;
	}

	return FPOL_OK;
}

int fpol_find_app(const struct fpol_view *v, u32 appid, struct fpol_app *out)
{
	u32 lo = 0, hi = v->n_apps;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;
		const u8 *p = v->base + v->apps_off + mid * FPOL_APP_ENTRY_SIZE;
		u32 id = get_le32(p);

		if (id == appid) {
			if (out) {
				out->appid = id;
				out->flags = get_le32(p + 4);
				out->profile_id = get_le32(p + 8);
			}
			return 1;
		}
		if (id < appid)
			lo = mid + 1;
		else
			hi = mid;
	}
	return 0;
}

/* Compare a NUL-padded policy name with a NUL-terminated string. */
static int name_eq(const u8 *field, const char *s)
{
	u32 i;

	for (i = 0; i < FPOL_NAME_LEN; i++) {
		if ((u8)s[i] != field[i])
			return 0;
		if (!s[i])
			return 1;
	}
	return 0;
}

static int name_prefix(const u8 *prefix, const char *s)
{
	u32 i;

	for (i = 0; i < FPOL_NAME_LEN && prefix[i]; i++) {
		if ((u8)s[i] != prefix[i])
			return 0;
	}
	return 1;
}

int fpol_tunnel_match(const struct fpol_view *v, const char *ifname,
		      const char *kind)
{
	u32 i;

	if (!ifname || !kind)
		return 0;
	for (i = 0; i < v->n_tunnels; i++) {
		const u8 *p = v->base + v->tunnels_off +
			      i * FPOL_TUNNEL_ENTRY_SIZE;

		if (name_eq(p, ifname) && name_eq(p + FPOL_NAME_LEN, kind))
			return 1;
	}
	return 0;
}

int fpol_exempt_match(const struct fpol_view *v, u32 appid,
		      const char *ifname)
{
	u32 i;

	if (!ifname)
		return 0;
	for (i = 0; i < v->n_exempt; i++) {
		const u8 *p = v->base + v->exempt_off +
			      i * FPOL_EXEMPT_ENTRY_SIZE;

		if (get_le32(p) == appid && name_prefix(p + 4, ifname))
			return 1;
	}
	return 0;
}

int fpol_profile(const struct fpol_view *v, u32 profile_id,
		 const u8 **data, u32 *len)
{
	const u8 *p;

	if (profile_id == FPOL_PROFILE_NONE || profile_id >= v->n_profiles)
		return 0;
	p = v->base + v->profiles_off + profile_id * FPOL_PROFILE_ENTRY_SIZE;
	*data = v->base + get_le32(p);
	*len = get_le32(p + 4);
	return 1;
}
