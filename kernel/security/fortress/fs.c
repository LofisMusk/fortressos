// SPDX-License-Identifier: GPL-2.0
/*
 * securityfs interface: /sys/kernel/security/fortress/
 *
 *   status        (0444) state and counters, one "key: value" per line
 *   policy        (0600) write a complete policy blob in a single write()
 *   self/profile  (0444) identity profile of the calling uid (-ENOENT if
 *                        none); zygote reads it right after setuid
 *   enforce       (0600) CONFIG_SECURITY_FORTRESS_DEVELOP only
 *
 * init.rc hands "policy" to the system user; SELinux further restricts
 * it to system_server. The kernel also checks the writer's euid itself.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

#include "fortress.h"

static bool policy_writer_ok(void)
{
	kuid_t euid = current_euid();

	if (current_user_ns() != &init_user_ns)
		return false;
	return uid_eq(euid, GLOBAL_ROOT_UID) ||
	       uid_eq(euid, KUIDT_INIT(FORTRESS_AID_SYSTEM));
}

static ssize_t policy_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	if (!policy_writer_ok())
		return -EPERM;
	/* The whole blob must arrive in one write(); no partial updates. */
	if (*ppos != 0)
		return -EINVAL;

	err = fortress_policy_load((const u8 __user *)buf, count);
	if (err)
		return err;
	*ppos += count;
	return count;
}

static const struct file_operations policy_fops = {
	.write	= policy_write,
	.llseek	= generic_file_llseek,
};

static int status_show(struct seq_file *m, void *v)
{
	struct fortress_policy *p;

	rcu_read_lock();
	p = rcu_dereference(fortress_active_policy);
	seq_printf(m, "state: %s\n", p ? "loaded" : "unloaded");
	seq_printf(m, "enforce: %d\n", fortress_enforce() ? 1 : 0);
	if (p) {
		seq_printf(m, "serial: %u\n", p->view.serial);
		seq_printf(m, "apps: %u\n", p->view.n_apps);
		seq_printf(m, "tunnels: %u\n", p->view.n_tunnels);
		seq_printf(m, "exempt: %u\n", p->view.n_exempt);
		seq_printf(m, "profiles: %u\n", p->view.n_profiles);
	}
	rcu_read_unlock();

	seq_printf(m, "loads: %lld\n", atomic64_read(&fortress_stats.loads));
	seq_printf(m, "load_failures: %lld\n",
		   atomic64_read(&fortress_stats.load_failures));
	seq_printf(m, "deny_gate: %lld\n",
		   atomic64_read(&fortress_stats.deny_gate));
	seq_printf(m, "deny_net: %lld\n",
		   atomic64_read(&fortress_stats.deny_net));
	seq_printf(m, "deny_ipc: %lld\n",
		   atomic64_read(&fortress_stats.deny_ipc));
	seq_printf(m, "deny_ident: %lld\n",
		   atomic64_read(&fortress_stats.deny_ident));
	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	return single_open(file, status_show, NULL);
}

static const struct file_operations status_fops = {
	.open		= status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* Callers should read the profile in a single read() of 64 KiB. */
static ssize_t profile_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	u8 *kbuf;
	ssize_t len;

	kbuf = kvmalloc(FPOL_MAX_PROFILE_LEN, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	len = fortress_profile_copy(current_uid(), kbuf, FPOL_MAX_PROFILE_LEN);
	if (len >= 0)
		len = simple_read_from_buffer(buf, count, ppos, kbuf, len);
	kvfree(kbuf);
	return len;
}

static const struct file_operations profile_fops = {
	.read	= profile_read,
	.llseek	= generic_file_llseek,
};

#ifdef CONFIG_SECURITY_FORTRESS_DEVELOP
static ssize_t enforce_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	char tmp[4];
	int len = scnprintf(tmp, sizeof(tmp), "%d\n",
			    fortress_enforce() ? 1 : 0);

	return simple_read_from_buffer(buf, count, ppos, tmp, len);
}

static ssize_t enforce_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	bool val;
	int err;

	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	err = kstrtobool_from_user(buf, count, &val);
	if (err)
		return err;
	WRITE_ONCE(fortress_enforcing, val);
	pr_notice("enforce=%d set by pid=%d\n", val, task_pid_nr(current));
	return count;
}

static const struct file_operations enforce_fops = {
	.read	= enforce_read,
	.write	= enforce_write,
	.llseek	= generic_file_llseek,
};
#endif

int fortress_securityfs_init(void)
{
	struct dentry *dir, *self, *d;

	dir = securityfs_create_dir("fortress", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	d = securityfs_create_file("status", 0444, dir, NULL, &status_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
	d = securityfs_create_file("policy", 0600, dir, NULL, &policy_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);

	self = securityfs_create_dir("self", dir);
	if (IS_ERR(self))
		return PTR_ERR(self);
	d = securityfs_create_file("profile", 0444, self, NULL, &profile_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);

#ifdef CONFIG_SECURITY_FORTRESS_DEVELOP
	d = securityfs_create_file("enforce", 0600, dir, NULL, &enforce_fops);
	if (IS_ERR(d))
		return PTR_ERR(d);
#endif
	return 0;
}
