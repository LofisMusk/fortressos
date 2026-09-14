// SPDX-License-Identifier: GPL-2.0
/*
 * Identity Guard: the kernel half of Phase 3.
 *
 * Two classes of leak are closed here for every untrusted uid. Neither
 * needs a policy, so both also hold in the UNLOADED state:
 *
 *   procfs / sysfs   files carrying hardware or network identity: MAC
 *                    addresses, SoC and eMMC serials, the device tree, the
 *                    LAN neighbour table, and every socket on the device.
 *                    The rules are in idpath.c.
 *
 *   rtnetlink        RTM_GETLINK returns the MAC of every interface and
 *                    RTM_GETADDR/GETROUTE the whole network layout, so an
 *                    app does not get an AF_NETLINK socket on the affected
 *                    families at all. Refusing the socket rather than
 *                    filtering messages also closes the multicast path,
 *                    where the kernel pushes link notifications unasked
 *                    and no message of the app's ever passes a hook.
 *
 * What a virtual identity should *say* is policy and comes from
 * self/profile. What an app must never see is not, so it is compiled in.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/magic.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/socket.h>
#include <net/sock.h>

#include "fortress.h"
#include "idpath.h"

static bool uid_restricted(kuid_t kuid)
{
	return fortress_is_untrusted_class(fortress_classify(kuid));
}

static int ident_deny(atomic64_t *counter)
{
	atomic64_inc(counter);
	return fortress_enforce() ? -EACCES : 0;
}

static const char *mode_prefix(void)
{
	return fortress_enforce() ? "" : "(permissive) ";
}

/* ---- procfs and sysfs ------------------------------------------------- */

static int deny_open(kuid_t kuid, const char *fs, const char *path)
{
	pr_notice_ratelimited("%sdeny open uid=%u pid=%d %s%s\n",
			      mode_prefix(), fortress_uid(kuid),
			      task_pid_nr(current), fs, path);
	return ident_deny(&fortress_stats.deny_ident);
}

int fortress_file_open(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	const char *fsname;
	enum fid_fs fs;
	char *buf, *path;
	int ret = 0;

	switch (dentry->d_sb->s_magic) {
	case PROC_SUPER_MAGIC:
		fs = FID_FS_PROC;
		fsname = "/proc";
		break;
	case SYSFS_MAGIC:
		fs = FID_FS_SYS;
		fsname = "/sys";
		break;
	default:
		return 0;
	}
	if (!uid_restricted(file->f_cred->uid))
		return 0;

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf) {
		/* No way to tell: refuse. Apps never have to read these. */
		if (!fortress_enforce())
			return 0;
		return -ENOMEM;
	}

	/*
	 * The path within the filesystem, so it cannot be changed by where
	 * procfs or sysfs happen to be mounted.
	 */
	path = dentry_path_raw(dentry, buf, PAGE_SIZE);
	if (IS_ERR(path))
		ret = deny_open(file->f_cred->uid, fsname, "/<path too long>");
	else if (fid_path_denied(fs, path))
		ret = deny_open(file->f_cred->uid, fsname, path);

	free_page((unsigned long)buf);
	return ret;
}

/* ---- rtnetlink and friends -------------------------------------------- */

/*
 * Netlink families that enumerate interfaces, addresses, routes, IPsec
 * state or the sockets of other uids. NETLINK_GENERIC is deliberately not
 * here: nl80211 scan results are location data and belong to Phase 5.
 */
static bool netlink_restricted(int protocol)
{
	switch (protocol) {
	case NETLINK_ROUTE:
	case NETLINK_SOCK_DIAG:
	case NETLINK_XFRM:
	case NETLINK_NETFILTER:
		return true;
	default:
		return false;
	}
}

static int deny_netlink(kuid_t kuid, int protocol, const char *what)
{
	pr_notice_ratelimited("%sdeny netlink %s uid=%u pid=%d proto=%d\n",
			      mode_prefix(), what, fortress_uid(kuid),
			      task_pid_nr(current), protocol);
	return ident_deny(&fortress_stats.deny_netlink);
}

int fortress_socket_create(int family, int type, int protocol, int kern)
{
	if (kern || family != AF_NETLINK || !netlink_restricted(protocol))
		return 0;
	if (!uid_restricted(current_uid()))
		return 0;
	return deny_netlink(current_uid(), protocol, "socket");
}

/*
 * A socket the app did not create itself, e.g. one handed to it over
 * SCM_RIGHTS by a platform process: it never passed socket_create in this
 * uid. Either end being untrusted is enough to refuse the request.
 */
int fortress_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	if (!sk || !netlink_restricted(sk->sk_protocol))
		return 0;
	if (!uid_restricted(current_uid()) && !uid_restricted(sk->sk_uid))
		return 0;
	return deny_netlink(current_uid(), sk->sk_protocol, "send");
}
