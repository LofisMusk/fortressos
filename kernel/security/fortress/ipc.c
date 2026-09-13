// SPDX-License-Identifier: GPL-2.0
/*
 * Application isolation for AF_UNIX sockets.
 *
 * Two different untrusted uids (apps, SDK sandboxes, isolated processes)
 * may not talk to each other over named or abstract unix sockets. Talking
 * to platform daemons (system uids) is unaffected, as is anything between
 * sockets of the same uid, e.g. a socketpair() handed to a child process.
 *
 * The uid used is the socket creator's (sk_uid), not current's: that is
 * what identifies the endpoint, and unprivileged code cannot change it.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/net.h>
#include <net/sock.h>

#include "fortress.h"

static bool uid_is_trusted_app(const struct fortress_policy *p, kuid_t kuid)
{
	struct fpol_app app;

	if (!p || fortress_classify(kuid) != FPOL_CLASS_APP)
		return false;
	if (!fpol_find_app(&p->view, fpol_appid(fortress_uid(kuid)), &app))
		return false;
	return app.flags & FPOL_APP_TRUSTED;
}

static int ipc_check(const struct sock *a, const struct sock *b)
{
	struct fortress_policy *p;
	kuid_t ua, ub;
	bool deny;

	if (!a || !b)
		return 0;
	ua = a->sk_uid;
	ub = b->sk_uid;
	if (uid_eq(ua, ub))
		return 0;
	if (!fortress_is_untrusted_class(fortress_classify(ua)) ||
	    !fortress_is_untrusted_class(fortress_classify(ub)))
		return 0;

	rcu_read_lock();
	p = rcu_dereference(fortress_active_policy);
	deny = !uid_is_trusted_app(p, ua) && !uid_is_trusted_app(p, ub);
	rcu_read_unlock();
	if (!deny)
		return 0;

	atomic64_inc(&fortress_stats.deny_ipc);
	pr_notice_ratelimited("%sdeny unix ipc %u -> %u\n",
			      fortress_enforce() ? "" : "(permissive) ",
			      fortress_uid(ua), fortress_uid(ub));
	return fortress_enforce() ? -EACCES : 0;
}

int fortress_unix_stream_connect(struct sock *sock, struct sock *other,
				 struct sock *newsk)
{
	return ipc_check(sock, other);
}

int fortress_unix_may_send(struct socket *sock, struct socket *other)
{
	if (!sock || !other)
		return 0;
	return ipc_check(sock->sk, other->sk);
}
