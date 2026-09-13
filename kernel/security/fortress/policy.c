// SPDX-License-Identifier: GPL-2.0
/*
 * Fortress policy state: atomic, all-or-nothing replacement under RCU.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "fortress.h"

struct fortress_policy __rcu *fortress_active_policy;
struct fortress_stats fortress_stats;

static DEFINE_MUTEX(fortress_policy_mutex);

static void fortress_policy_free_rcu(struct rcu_head *head)
{
	kvfree(container_of(head, struct fortress_policy, rcu));
}

/*
 * Copy, validate and publish a new policy. On any failure the active
 * policy (or the UNLOADED state) is left untouched.
 */
int fortress_policy_load(const u8 __user *ubuf, size_t len)
{
	struct fortress_policy *np, *old;
	int err;

	if (len < FPOL_HEADER_SIZE || len > FPOL_MAX_SIZE) {
		atomic64_inc(&fortress_stats.load_failures);
		return -EINVAL;
	}

	np = kvmalloc(sizeof(*np) + len, GFP_KERNEL);
	if (!np)
		return -ENOMEM;
	if (copy_from_user(np->blob, ubuf, len)) {
		kvfree(np);
		return -EFAULT;
	}
	np->len = len;

	err = fpol_parse(np->blob, len, &np->view);
	if (err) {
		pr_warn("policy rejected: %s\n", fpol_strerror(err));
		atomic64_inc(&fortress_stats.load_failures);
		kvfree(np);
		return -EINVAL;
	}

	mutex_lock(&fortress_policy_mutex);
	old = rcu_dereference_protected(fortress_active_policy,
					lockdep_is_held(&fortress_policy_mutex));
	rcu_assign_pointer(fortress_active_policy, np);
	mutex_unlock(&fortress_policy_mutex);

	if (old)
		call_rcu(&old->rcu, fortress_policy_free_rcu);

	atomic64_inc(&fortress_stats.loads);
	pr_info("policy loaded: serial=%u apps=%u tunnels=%u exempt=%u profiles=%u\n",
		np->view.serial, np->view.n_apps, np->view.n_tunnels,
		np->view.n_exempt, np->view.n_profiles);
	return 0;
}

/*
 * Copy the identity profile assigned to @kuid into @dst (capacity @cap,
 * at least FPOL_MAX_PROFILE_LEN). Returns its length or -ENOENT.
 */
ssize_t fortress_profile_copy(kuid_t kuid, u8 *dst, size_t cap)
{
	struct fortress_policy *p;
	struct fpol_app app;
	const u8 *data;
	u32 len;
	ssize_t ret = -ENOENT;

	if (fortress_classify(kuid) != FPOL_CLASS_APP)
		return -ENOENT;

	rcu_read_lock();
	p = rcu_dereference(fortress_active_policy);
	if (p && fpol_find_app(&p->view, fpol_appid(fortress_uid(kuid)), &app) &&
	    fpol_profile(&p->view, app.profile_id, &data, &len) &&
	    len <= cap) {
		memcpy(dst, data, len);
		ret = len;
	}
	rcu_read_unlock();
	return ret;
}
