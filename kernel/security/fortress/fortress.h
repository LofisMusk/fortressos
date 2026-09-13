/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fortress LSM - internal interfaces.
 */
#ifndef _SECURITY_FORTRESS_H
#define _SECURITY_FORTRESS_H

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>

#include "policy_parse.h"

#define FORTRESS_AID_SYSTEM	1000	/* AID_SYSTEM: system_server */

/* An immutable, validated policy. Replaced wholesale under RCU. */
struct fortress_policy {
	struct rcu_head rcu;
	struct fpol_view view;
	size_t len;
	u8 blob[];
};

/* NULL until the first successful load: the UNLOADED (deny-all) state. */
extern struct fortress_policy __rcu *fortress_active_policy;

struct fortress_stats {
	atomic64_t loads;
	atomic64_t load_failures;
	atomic64_t deny_gate;
	atomic64_t deny_net;
	atomic64_t deny_ipc;
};
extern struct fortress_stats fortress_stats;

#ifdef CONFIG_SECURITY_FORTRESS_DEVELOP
extern bool fortress_enforcing;
static inline bool fortress_enforce(void)
{
	return READ_ONCE(fortress_enforcing);
}
#else
/* Release builds: enforcement cannot be turned off, not even by root. */
static inline bool fortress_enforce(void)
{
	return true;
}
#endif

static inline u32 fortress_uid(kuid_t kuid)
{
	return from_kuid(&init_user_ns, kuid);
}

static inline enum fpol_uid_class fortress_classify(kuid_t kuid)
{
	return fpol_classify_appid(fpol_appid(fortress_uid(kuid)));
}

/* Any class that is not part of the platform is treated as hostile. */
static inline bool fortress_is_untrusted_class(enum fpol_uid_class c)
{
	return c != FPOL_CLASS_SYSTEM;
}

/* policy.c */
int fortress_policy_load(const u8 __user *ubuf, size_t len);
ssize_t fortress_profile_copy(kuid_t kuid, u8 *dst, size_t cap);

/* fs.c */
int fortress_securityfs_init(void);

/* gate.c */
int fortress_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags);

/* ipc.c */
struct sock;
struct socket;
int fortress_unix_stream_connect(struct sock *sock, struct sock *other,
				 struct sock *newsk);
int fortress_unix_may_send(struct socket *sock, struct socket *other);

/* netguard.c */
int fortress_netguard_init(void);

/*
 * An initialisation step the security model depends on has failed. In
 * enforcing mode the kernel refuses to continue: booting without a
 * guard would silently expose real identity and network paths.
 */
#define fortress_fatal(fmt, ...)					\
	do {								\
		if (fortress_enforce())					\
			panic("fortress: " fmt, ##__VA_ARGS__);		\
		pr_err("(develop) " fmt, ##__VA_ARGS__);		\
	} while (0)

#endif /* _SECURITY_FORTRESS_H */
