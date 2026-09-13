// SPDX-License-Identifier: GPL-2.0
/*
 * Fortress LSM - registration and boot-time wiring.
 *
 * Fortress is a minor LSM stacked next to SELinux. It has no userspace
 * daemon: enforcement lives entirely in these hooks and in the netfilter
 * hooks of netguard.c. Userspace (system_server) only supplies policy.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>

#include "fortress.h"

static bool fortress_lsm_active __ro_after_init;

#ifdef CONFIG_SECURITY_FORTRESS_DEVELOP
bool fortress_enforcing = !IS_ENABLED(CONFIG_SECURITY_FORTRESS_DEVELOP_PERMISSIVE);

static int __init fortress_enforce_setup(char *str)
{
	bool val;

	if (!kstrtobool(str, &val))
		fortress_enforcing = val;
	return 1;
}
__setup("fortress.enforce=", fortress_enforce_setup);
#endif

static struct security_hook_list fortress_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_fix_setuid, fortress_task_fix_setuid),
	LSM_HOOK_INIT(unix_stream_connect, fortress_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, fortress_unix_may_send),
};

static int __init fortress_lsm_init(void)
{
	security_add_hooks(fortress_hooks, ARRAY_SIZE(fortress_hooks),
			   "fortress");
	fortress_lsm_active = true;
	pr_info("initialized, %s\n",
		fortress_enforce() ? "enforcing" : "PERMISSIVE (develop)");
	return 0;
}

DEFINE_LSM(fortress) = {
	.name = "fortress",
	.init = fortress_lsm_init,
};

/*
 * Runs after the core network and securityfs are up but long before
 * userspace. Every failure here is fatal in enforcing mode.
 */
static int __init fortress_late_init(void)
{
	int err;

	if (!fortress_lsm_active) {
		/* Built in but left out of CONFIG_LSM / lsm=: refuse to boot. */
		fortress_fatal("LSM not enabled, add \"fortress\" to CONFIG_LSM\n");
		return 0;
	}

	err = fortress_netguard_init();
	if (err)
		fortress_fatal("network guard init failed: %d\n", err);

	err = fortress_securityfs_init();
	if (err)
		fortress_fatal("securityfs init failed: %d\n", err);

	return 0;
}
fs_initcall(fortress_late_init);
