// SPDX-License-Identifier: GPL-2.0
/*
 * Host-side tests for the kernel's policy parser (policy_parse.c is
 * compiled unchanged). Build with ASan/UBSan: see Makefile.
 *
 *   host_test <good.bin>
 *
 * good.bin must be tests/kernel/policy/good.json compiled by fpol.py.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "idpath.h"
#include "policy_parse.h"

static int failures;

#define CHECK(cond) do {						\
	if (!(cond)) {							\
		fprintf(stderr, "%s:%d: CHECK failed: %s\n",		\
			__FILE__, __LINE__, #cond);			\
		failures++;						\
	}								\
} while (0)

static u8 *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	u8 *buf;
	long n;

	if (!f) {
		perror(path);
		exit(2);
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n);
	if (!buf || fread(buf, 1, n, f) != (size_t)n) {
		perror("read");
		exit(2);
	}
	fclose(f);
	*len = n;
	return buf;
}

static u32 le32(const u8 *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | (u32)p[3] << 24;
}

static void put_le32(u8 *p, u32 v)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

/* Parse a private heap copy so ASan catches any out-of-bounds read. */
static int parse_copy(const u8 *blob, size_t len, struct fpol_view *v)
{
	u8 *copy = malloc(len ? len : 1);
	int err;

	memcpy(copy, blob, len);
	err = fpol_parse(copy, len, v);
	free(copy);
	return err;
}

static void test_valid(const u8 *blob, size_t len)
{
	struct fpol_view v;
	struct fpol_app app;
	const u8 *data;
	u32 plen;

	CHECK(fpol_parse(blob, len, &v) == FPOL_OK);
	CHECK(v.serial == 1 && v.n_apps == 4 && v.n_tunnels == 1);
	CHECK(v.n_exempt == 1 && v.n_profiles == 1);

	CHECK(fpol_find_app(&v, 10050, &app));
	CHECK(app.flags == FPOL_APP_NET && app.profile_id == 0);
	CHECK(fpol_find_app(&v, 10052, &app) && app.flags == 0);
	CHECK(fpol_find_app(&v, 10060, &app) &&
	      app.flags == (FPOL_APP_NET | FPOL_APP_TRUSTED));
	CHECK(!fpol_find_app(&v, 10053, NULL));
	CHECK(!fpol_find_app(&v, 0, NULL));
	CHECK(!fpol_find_app(&v, 99999, NULL));

	CHECK(fpol_tunnel_match(&v, "fwg0", "tun"));
	CHECK(!fpol_tunnel_match(&v, "fwg0", "wireguard"));
	CHECK(!fpol_tunnel_match(&v, "fwg", "tun"));
	CHECK(!fpol_tunnel_match(&v, "fwg00", "tun"));
	CHECK(!fpol_tunnel_match(&v, "fwg0", NULL));

	CHECK(fpol_exempt_match(&v, 1073, "phys0"));
	CHECK(fpol_exempt_match(&v, 1073, "phys"));
	CHECK(!fpol_exempt_match(&v, 1073, "phy"));
	CHECK(!fpol_exempt_match(&v, 1000, "phys0"));

	CHECK(fpol_profile(&v, 0, &data, &plen));
	CHECK(plen == strlen("ro.product.brand=google\nro.product.model=Pixel 9\n"));
	CHECK(memcmp(data, "ro.product.brand=google\n", 24) == 0);
	CHECK(!fpol_profile(&v, 1, &data, &plen));
	CHECK(!fpol_profile(&v, FPOL_PROFILE_NONE, &data, &plen));
}

static void test_classify(void)
{
	CHECK(fpol_classify_appid(0) == FPOL_CLASS_SYSTEM);
	CHECK(fpol_classify_appid(1000) == FPOL_CLASS_SYSTEM);
	CHECK(fpol_classify_appid(9999) == FPOL_CLASS_SYSTEM);
	CHECK(fpol_classify_appid(10000) == FPOL_CLASS_APP);
	CHECK(fpol_classify_appid(19999) == FPOL_CLASS_APP);
	CHECK(fpol_classify_appid(20000) == FPOL_CLASS_SANDBOX);
	CHECK(fpol_classify_appid(90000) == FPOL_CLASS_ISOLATED);
	CHECK(fpol_classify_appid(99999) == FPOL_CLASS_ISOLATED);
	CHECK(fpol_classify_appid(65534) == FPOL_CLASS_SYSTEM);
	CHECK(fpol_appid(1010050) == 10050);	/* user 10 */
}

/* Every strict prefix of a valid blob must be rejected. */
static void test_truncation(const u8 *blob, size_t len)
{
	struct fpol_view v;
	size_t n;

	for (n = 0; n < len; n++)
		CHECK(parse_copy(blob, n, &v) != FPOL_OK);
}

/* Arbitrary single-byte corruption must never crash or read OOB. */
static void test_bitflips(const u8 *blob, size_t len)
{
	u8 *m = malloc(len);
	struct fpol_view v;
	size_t i;
	int bit;

	for (i = 0; i < len; i++) {
		for (bit = 0; bit < 8; bit++) {
			memcpy(m, blob, len);
			m[i] ^= 1u << bit;
			if (parse_copy(m, len, &v) == FPOL_OK) {
				/* Accepted mutations must still be safe to query. */
				u8 *copy = malloc(len);
				const u8 *d;
				u32 l, k;

				memcpy(copy, m, len);
				CHECK(fpol_parse(copy, len, &v) == FPOL_OK);
				for (k = 0; k < v.n_profiles; k++)
					fpol_profile(&v, k, &d, &l);
				fpol_find_app(&v, 10050, NULL);
				fpol_tunnel_match(&v, "fwg0", "tun");
				fpol_exempt_match(&v, 1073, "phys0");
				free(copy);
			}
		}
	}
	free(m);
}

typedef void (*mutator)(u8 *m, size_t len);

static void expect_err(const u8 *blob, size_t len, mutator fn, int want,
		       const char *name)
{
	u8 *m = malloc(len);
	struct fpol_view v;
	int got;

	memcpy(m, blob, len);
	fn(m, len);
	got = parse_copy(m, len, &v);
	if (got != want) {
		fprintf(stderr, "%s: want %s, got %s\n", name,
			fpol_strerror(want), fpol_strerror(got));
		failures++;
	}
	free(m);
}

#define APPS(m)		((m) + le32((m) + 24))
#define TUNNELS(m)	((m) + le32((m) + 32))
#define EXEMPT(m)	((m) + le32((m) + 40))
#define PROFILES(m)	((m) + le32((m) + 48))

static void m_magic(u8 *m, size_t l)	{ m[0] = 'X'; }
static void m_version(u8 *m, size_t l)	{ m[4] = 2; }
static void m_hsize(u8 *m, size_t l)	{ m[6] = 32; }
static void m_total(u8 *m, size_t l)	{ put_le32(m + 8, l + 4); }
static void m_flags(u8 *m, size_t l)	{ put_le32(m + 12, 0x80); }
static void m_reserved(u8 *m, size_t l)	{ m[60] = 1; }
static void m_napps(u8 *m, size_t l)	{ put_le32(m + 20, 10001); }
static void m_napps_oob(u8 *m, size_t l) { put_le32(m + 20, 500); }
static void m_misalign(u8 *m, size_t l)	{ put_le32(m + 24, le32(m + 24) + 2); }
static void m_into_hdr(u8 *m, size_t l)	{ put_le32(m + 24, 16); }
static void m_empty_off(u8 *m, size_t l) { put_le32(m + 20, 0); }
static void m_unsorted(u8 *m, size_t l)	{ put_le32(APPS(m) + 12, 10050); }
static void m_sysapp(u8 *m, size_t l)	{ put_le32(APPS(m), 1000); }
static void m_isoapp(u8 *m, size_t l)	{ put_le32(APPS(m) + 36, 90001); }
static void m_appflags(u8 *m, size_t l)	{ put_le32(APPS(m) + 4, 4); }
static void m_dangling(u8 *m, size_t l)	{ put_le32(APPS(m) + 8, 1); }
static void m_name_nul(u8 *m, size_t l)	{ memset(TUNNELS(m), 'a', 16); }
static void m_name_char(u8 *m, size_t l) { TUNNELS(m)[1] = '/'; }
static void m_name_tail(u8 *m, size_t l) { TUNNELS(m)[15] = 'x'; }
static void m_name_empty(u8 *m, size_t l) { TUNNELS(m)[16] = 0; }
static void m_exempt_app(u8 *m, size_t l) { put_le32(EXEMPT(m), 10050); }
static void m_prof_len(u8 *m, size_t l)	{ put_le32(PROFILES(m) + 4, 70000); }
static void m_prof_oob(u8 *m, size_t l)	{ put_le32(PROFILES(m), l - 2); }
static void m_prof_hdr(u8 *m, size_t l)	{ put_le32(PROFILES(m), 8); }
static void m_prof_wrap(u8 *m, size_t l) { put_le32(PROFILES(m), 0xfffffff0u); }

static void test_negative(const u8 *b, size_t l)
{
	expect_err(b, l, m_magic, FPOL_E_MAGIC, "magic");
	expect_err(b, l, m_version, FPOL_E_VERSION, "version");
	expect_err(b, l, m_hsize, FPOL_E_SIZE, "header size");
	expect_err(b, l, m_total, FPOL_E_SIZE, "total size");
	expect_err(b, l, m_flags, FPOL_E_FLAGS, "global flags");
	expect_err(b, l, m_reserved, FPOL_E_RESERVED, "reserved");
	expect_err(b, l, m_napps, FPOL_E_COUNT, "apps count");
	expect_err(b, l, m_napps_oob, FPOL_E_BOUNDS, "apps oob");
	expect_err(b, l, m_misalign, FPOL_E_ALIGN, "misaligned");
	expect_err(b, l, m_into_hdr, FPOL_E_BOUNDS, "section in header");
	expect_err(b, l, m_empty_off, FPOL_E_BOUNDS, "empty section offset");
	expect_err(b, l, m_unsorted, FPOL_E_ORDER, "unsorted apps");
	expect_err(b, l, m_sysapp, FPOL_E_APPID, "system uid as app");
	expect_err(b, l, m_isoapp, FPOL_E_APPID, "isolated uid as app");
	expect_err(b, l, m_appflags, FPOL_E_FLAGS, "app flags");
	expect_err(b, l, m_dangling, FPOL_E_PROFILE, "dangling profile");
	expect_err(b, l, m_name_nul, FPOL_E_NAME, "name without NUL");
	expect_err(b, l, m_name_char, FPOL_E_NAME, "name with '/'");
	expect_err(b, l, m_name_tail, FPOL_E_NAME, "name garbage tail");
	expect_err(b, l, m_name_empty, FPOL_E_NAME, "empty kind");
	expect_err(b, l, m_exempt_app, FPOL_E_APPID, "app exemption");
	expect_err(b, l, m_prof_len, FPOL_E_PROFILE, "profile too long");
	expect_err(b, l, m_prof_oob, FPOL_E_BOUNDS, "profile oob");
	expect_err(b, l, m_prof_hdr, FPOL_E_BOUNDS, "profile in header");
	expect_err(b, l, m_prof_wrap, FPOL_E_BOUNDS, "profile offset wrap");
}

/* ---- Identity Guard path rules (idpath.c) ----------------------------- */

static void test_path_match(void)
{
	/* Literal segments. */
	CHECK(fid_path_match("/cpuinfo", "/cpuinfo"));
	CHECK(!fid_path_match("/cpuinfo", "/cpuinfo2"));
	CHECK(!fid_path_match("/cpuinfo", "/cpu"));
	CHECK(!fid_path_match("/cpuinfo", "/cpuinfo/x"));
	CHECK(!fid_path_match("/cpuinfo", "/x/cpuinfo"));
	CHECK(!fid_path_match("/cpuinfo", "/"));

	/* "*" is exactly one segment. */
	CHECK(fid_path_match("/*/net/tcp", "/1/net/tcp"));
	CHECK(fid_path_match("/*/net/tcp", "/thread-self/net/tcp"));
	CHECK(!fid_path_match("/*/net/tcp", "/net/tcp"));
	CHECK(!fid_path_match("/*/net/tcp", "/1/2/net/tcp"));

	/* "**" is any number of segments, including none. */
	CHECK(fid_path_match("/net/**", "/net"));
	CHECK(fid_path_match("/net/**", "/net/arp"));
	CHECK(fid_path_match("/net/**", "/net/a/b/c/d"));
	CHECK(!fid_path_match("/net/**", "/netx"));
	CHECK(!fid_path_match("/net/**", "/"));
	CHECK(fid_path_match("/**/address", "/address"));
	CHECK(fid_path_match("/**/address", "/devices/x/net/eth0/address"));
	CHECK(!fid_path_match("/**/address", "/devices/x/addressx"));
	CHECK(!fid_path_match("/**/address", "/devices/address/x"));
	CHECK(fid_path_match("/devices/**/net/**", "/devices/a/b/net/eth0/x"));
	CHECK(fid_path_match("/devices/**/net/**", "/devices/net"));
	CHECK(!fid_path_match("/devices/**/net/**", "/class/net/eth0"));

	/* Backtracking has to try every position of "**". */
	CHECK(fid_path_match("/**/net/**", "/a/net/b/net/c"));
	CHECK(fid_path_match("/**/a/a/b", "/a/a/a/b"));
	CHECK(!fid_path_match("/**/a/a/b", "/a/a/a/c"));

	/* Repeated and trailing slashes are not a way around a rule. */
	CHECK(fid_path_match("/net/**", "//net//arp"));
	CHECK(fid_path_match("/cpuinfo", "/cpuinfo/"));
}

static void test_path_denied(void)
{
	/* procfs: the whole network tree, by either spelling. */
	CHECK(fid_path_denied(FID_FS_PROC, "/1234/net/arp"));
	CHECK(fid_path_denied(FID_FS_PROC, "/1234/net/tcp6"));
	CHECK(fid_path_denied(FID_FS_PROC, "/1234/net/unix"));
	CHECK(fid_path_denied(FID_FS_PROC, "/1234/net"));
	CHECK(fid_path_denied(FID_FS_PROC, "/net/arp"));
	CHECK(fid_path_denied(FID_FS_PROC, "/cpuinfo"));
	CHECK(fid_path_denied(FID_FS_PROC, "/sys/kernel/random/boot_id"));
	/* ... but ordinary procfs stays readable. */
	CHECK(!fid_path_denied(FID_FS_PROC, "/1234/status"));
	CHECK(!fid_path_denied(FID_FS_PROC, "/1234/maps"));
	CHECK(!fid_path_denied(FID_FS_PROC, "/self/cmdline"));
	CHECK(!fid_path_denied(FID_FS_PROC, "/meminfo"));
	CHECK(!fid_path_denied(FID_FS_PROC, "/sys/kernel/random/uuid"));

	/* sysfs: MAC addresses through the class and the device path. */
	CHECK(fid_path_denied(FID_FS_SYS, "/class/net"));
	CHECK(fid_path_denied(FID_FS_SYS, "/class/net/wlan0/address"));
	CHECK(fid_path_denied(FID_FS_SYS,
			      "/devices/platform/soc/a000000.wifi/net/wlan0/address"));
	CHECK(fid_path_denied(FID_FS_SYS, "/class/bluetooth/hci0/address"));
	/* Serials: SoC, eMMC, USB, device tree. */
	CHECK(fid_path_denied(FID_FS_SYS, "/devices/soc0/serial_number"));
	CHECK(fid_path_denied(FID_FS_SYS,
			      "/devices/platform/soc/8804000.sdhci/mmc_host/mmc0/mmc0:0001/cid"));
	CHECK(fid_path_denied(FID_FS_SYS,
			      "/devices/virtual/android_usb/android0/iSerial"));
	CHECK(fid_path_denied(FID_FS_SYS, "/firmware/devicetree/base/serial-number"));
	CHECK(fid_path_denied(FID_FS_SYS, "/bus/usb/devices/usb1/serial"));
	/* ... but unrelated sysfs is untouched. */
	CHECK(!fid_path_denied(FID_FS_SYS, "/devices/system/cpu/online"));
	CHECK(!fid_path_denied(FID_FS_SYS, "/class/power_supply/battery/capacity"));
	CHECK(!fid_path_denied(FID_FS_SYS, "/kernel/mm/transparent_hugepage/enabled"));
}

int main(int argc, char **argv)
{
	size_t len;
	u8 *blob;

	if (argc != 2) {
		fprintf(stderr, "usage: %s good.bin\n", argv[0]);
		return 2;
	}
	blob = read_file(argv[1], &len);

	test_classify();
	test_path_match();
	test_path_denied();
	test_valid(blob, len);
	test_truncation(blob, len);
	test_bitflips(blob, len);
	test_negative(blob, len);

	free(blob);
	if (failures) {
		fprintf(stderr, "host_test: %d failure(s)\n", failures);
		return 1;
	}
	printf("host_test: all checks passed\n");
	return 0;
}
