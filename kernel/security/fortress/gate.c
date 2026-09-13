// SPDX-License-Identifier: GPL-2.0
/*
 * Identity Guard launch gate.
 *
 * Every Android app process is born when zygote (or installd, run-as, ...)
 * calls setresuid() into the app uid range. This hook is the single choke
 * point: a process may only become an app uid if an active policy exists
 * and, for installed apps, the policy carries an entry (and therefore a
 * virtual identity profile) for that app. Otherwise the transition fails
 * and the would-be app process is killed, so no app code ever runs
 * without the guard in place.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/cred.h>
#include <linux/sched/signal.h>

#include "fortress.h"

/* Returns true if the process may take on @kuid. */
static bool gate_allows(kuid_t kuid)
{
	struct fortress_policy *p;
	enum fpol_uid_class cls = fortress_classify(kuid);
	bool ok;

	if (!fortress_is_untrusted_class(cls))
		return true;

	rcu_read_lock();
	p = rcu_dereference(fortress_active_policy);
	if (!p)
		ok = false;			/* UNLOADED: nothing may launch */
	else if (cls == FPOL_CLASS_APP)
		ok = fpol_find_app(&p->view,
				   fpol_appid(fortress_uid(kuid)), NULL);
	else
		ok = true;			/* sandbox/isolated: dynamic uids */
	rcu_read_unlock();
	return ok;
}

int fortress_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags)
{
	kuid_t ids[4] = { new->uid, new->euid, new->suid, new->fsuid };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ids); i++) {
		if (gate_allows(ids[i]))
			continue;

		atomic64_inc(&fortress_stats.deny_gate);
		pr_notice_ratelimited("%sdeny setuid pid=%d comm=%s %u -> %u\n",
				      fortress_enforce() ? "" : "(permissive) ",
				      task_pid_nr(current), current->comm,
				      fortress_uid(old->uid),
				      fortress_uid(ids[i]));
		if (!fortress_enforce())
			return 0;
		/*
		 * Like SafeSetID: a privileged process that failed to drop to
		 * the target uid must not carry on with its old credentials.
		 */
		force_sig(SIGKILL);
		return -EPERM;
	}
	return 0;
}
