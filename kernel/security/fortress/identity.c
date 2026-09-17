// SPDX-License-Identifier: GPL-2.0
/*
 * Identity Guard, kernel half: keep hardware identity out of reach of
 * untrusted uids.
 *
 * Measured on a Galaxy A52s running LineageOS 23.2, a plain app could still
 * read the SoC id, /proc/cpuinfo and /proc/sys/kernel/random/boot_id. The
 * boot id is the worst of the three: every app on the device sees the same
 * value, so it is a ready-made cross-app correlation key.
 *
 * Everything below is a denial, not a substitution. The kernel can stop a
 * read; only zygote can hand an app a plausible fake, which is the
 * framework half of Phase 3.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/sock.h>
#include <uapi/linux/rtnetlink.h>

#include "fortress.h"

/* Our targets are short; anything longer is not one of them. */
#define FORTRESS_PATH_MAX 128

/* Paths as procfs reports them, i.e. without the /proc prefix. */
static const char * const proc_deny[] = {
	"/cpuinfo",			/* SoC revision, part numbers */
	"/cmdline",			/* androidboot.serialno, bootloader */
	"/version",			/* exact kernel build string */
	"/sys/kernel/random/boot_id",	/* same value for every app */
	"/net/arp",			/* the local network around the phone */
	"/net/route",
	"/net/if_inet6",
};

/*
 * sysfs reports the device path behind the /sys/class/... symlinks, so
 * "/sys/class/net/wlan0/address" arrives as ".../net/wlan0/address". Match
 * the tail instead of the pretty path.
 */
static const char * const sysfs_deny_suffix[] = {
	"/address",		/* MAC of any interface */
	"/serial",
	"/serial_number",
	"/unique_id",		/* eMMC/UFS identity */
	"/cid",
};

static bool ends_with(const char *path, const char *suffix)
{
	size_t plen = strlen(path);
	size_t slen = strlen(suffix);

	return plen >= slen && !strcmp(path + plen - slen, suffix);
}

static bool proc_is_identity(const char *path)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(proc_deny); i++) {
		if (!strcmp(path, proc_deny[i]))
			return true;
	}
	return false;
}

static bool sysfs_is_identity(const char *path)
{
	unsigned int i;

	/* Qualcomm publishes the SoC serial and machine name under soc0. */
	if (strstr(path, "/soc0/"))
		return true;
	for (i = 0; i < ARRAY_SIZE(sysfs_deny_suffix); i++) {
		if (ends_with(path, sysfs_deny_suffix[i]))
			return true;
	}
	return false;
}

int fortress_file_open(struct file *file)
{
	char buf[FORTRESS_PATH_MAX];
	struct super_block *sb;
	const char *path;
	bool identity;

	if (!fortress_is_untrusted_class(fortress_classify(current_uid())))
		return 0;

	sb = file->f_path.dentry->d_sb;
	if (sb->s_magic != PROC_SUPER_MAGIC && sb->s_magic != SYSFS_MAGIC)
		return 0;

	path = dentry_path_raw(file->f_path.dentry, buf, sizeof(buf));
	if (IS_ERR(path))
		return 0;

	identity = (sb->s_magic == PROC_SUPER_MAGIC) ? proc_is_identity(path)
						     : sysfs_is_identity(path);
	if (!identity)
		return 0;

	atomic64_inc(&fortress_stats.deny_ident);
	pr_notice_ratelimited("%sdeny read uid=%u %s%s\n",
			      fortress_enforce() ? "" : "(permissive) ",
			      fortress_uid(current_uid()),
			      sb->s_magic == PROC_SUPER_MAGIC ? "/proc" : "/sys",
			      path);
	return fortress_enforce() ? -EACCES : 0;
}

/*
 * RTM_GETLINK carries IFLA_ADDRESS, so a netlink dump is a way around the
 * framework's MAC restrictions. Denying it also breaks interface
 * enumeration (bionic's getifaddrs uses the same message), which is why
 * this is opt-in through the policy rather than always on.
 */
int fortress_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	struct fortress_policy *p;
	const struct nlmsghdr *nlh;
	bool blocked;

	if (sk->sk_protocol != NETLINK_ROUTE)
		return 0;
	if (!fortress_is_untrusted_class(fortress_classify(current_uid())))
		return 0;
	if (skb->len < NLMSG_HDRLEN)
		return 0;

	nlh = nlmsg_hdr(skb);
	if (nlh->nlmsg_type != RTM_GETLINK)
		return 0;

	rcu_read_lock();
	p = rcu_dereference(fortress_active_policy);
	blocked = p && (p->view.flags & FPOL_F_BLOCK_GETLINK);
	rcu_read_unlock();
	if (!blocked)
		return 0;

	atomic64_inc(&fortress_stats.deny_ident);
	pr_notice_ratelimited("%sdeny RTM_GETLINK uid=%u\n",
			      fortress_enforce() ? "" : "(permissive) ",
			      fortress_uid(current_uid()));
	return fortress_enforce() ? -EACCES : 0;
}
