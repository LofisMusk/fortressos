// SPDX-License-Identifier: GPL-2.0
/*
 * Network Guard: in-kernel, fail-closed egress policy.
 *
 * These are netfilter hooks registered by the kernel itself, not iptables
 * rules, so no userspace component (netd included) can flush or reorder
 * them. For every locally generated IPv4/IPv6 packet:
 *
 *   loopback                                   -> accept
 *   no owning socket / kernel socket           -> accept   (e.g. the
 *        in-kernel WireGuard UDP socket, TCP RST/ICMP control sockets)
 *   no policy loaded (UNLOADED)                -> drop
 *   out device is a policy tunnel              -> accept for system uids
 *        and for apps carrying FPOL_APP_NET; drop for sandbox/isolated
 *   system uid with (appid, ifprefix) exemption -> accept
 *   anything else                              -> drop
 *
 * So an app can never reach a physical interface, and if the tunnel is
 * down there is simply no permitted path: the kill switch is the default.
 * Forwarded traffic may only leave through a tunnel unless the policy
 * sets FPOL_F_ALLOW_FORWARD.
 */
#define pr_fmt(fmt) "fortress: " fmt

#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/rtnetlink.h>
#include <net/sock.h>

#include "fortress.h"

static bool dev_is_tunnel(const struct fortress_policy *p,
			  const struct net_device *dev)
{
	const char *kind = dev->rtnl_link_ops ? dev->rtnl_link_ops->kind : NULL;

	return fpol_tunnel_match(&p->view, dev->name, kind);
}

static bool uid_may_use(const struct fortress_policy *p, kuid_t kuid,
			const struct net_device *dev)
{
	u32 appid = fpol_appid(fortress_uid(kuid));
	struct fpol_app app;

	if (!p)
		return false;

	switch (fpol_classify_appid(appid)) {
	case FPOL_CLASS_APP:
		return dev_is_tunnel(p, dev) &&
		       fpol_find_app(&p->view, appid, &app) &&
		       (app.flags & FPOL_APP_NET);
	case FPOL_CLASS_SANDBOX:
	case FPOL_CLASS_ISOLATED:
		return false;
	case FPOL_CLASS_SYSTEM:
		break;
	}
	return dev_is_tunnel(p, dev) ||
	       fpol_exempt_match(&p->view, appid, dev->name);
}

static unsigned int net_deny(kuid_t kuid, const struct net_device *dev)
{
	atomic64_inc(&fortress_stats.deny_net);
	pr_notice_ratelimited("%sdeny egress uid=%u dev=%s\n",
			      fortress_enforce() ? "" : "(permissive) ",
			      fortress_uid(kuid), dev ? dev->name : "?");
	return fortress_enforce() ? NF_DROP_ERR(-EPERM) : NF_ACCEPT;
}

static unsigned int fortress_nf_out(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	const struct net_device *dev = state->out;
	struct fortress_policy *p;
	struct sock *sk;
	kuid_t kuid;
	bool ok;

	if (dev && (dev->flags & IFF_LOOPBACK))
		return NF_ACCEPT;

	/* The socket handing the packet to this layer, e.g. WireGuard's. */
	sk = state->sk ? state->sk : skb->sk;
	if (!sk)
		return NF_ACCEPT;	/* kernel generated, or forwarded */
	sk = sk_to_full_sk(sk);
	if (!sk)
		return NF_ACCEPT;
	if (!sk_fullsock(sk))
		return net_deny(INVALID_UID, dev);	/* owner unknown */
	if (sk->sk_kern_sock)
		return NF_ACCEPT;

	kuid = sk->sk_uid;
	if (!dev)
		return net_deny(kuid, dev);

	rcu_read_lock();
	p = rcu_dereference(fortress_active_policy);
	ok = uid_may_use(p, kuid, dev);
	rcu_read_unlock();

	return ok ? NF_ACCEPT : net_deny(kuid, dev);
}

static unsigned int fortress_nf_forward(void *priv, struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	const struct net_device *dev = state->out;
	struct fortress_policy *p;
	bool ok;

	if (dev && (dev->flags & IFF_LOOPBACK))
		return NF_ACCEPT;
	if (!dev)
		return net_deny(INVALID_UID, dev);

	rcu_read_lock();
	p = rcu_dereference(fortress_active_policy);
	ok = p && ((p->view.flags & FPOL_F_ALLOW_FORWARD) ||
		   dev_is_tunnel(p, dev));
	rcu_read_unlock();

	return ok ? NF_ACCEPT : net_deny(INVALID_UID, dev);
}

static const struct nf_hook_ops fortress_nf_ops[] = {
	{
		.hook		= fortress_nf_out,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FIRST,
	},
	{
		/* Last: sees the final route after mangle/NAT rerouting. */
		.hook		= fortress_nf_out,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_LAST,
	},
	{
		.hook		= fortress_nf_forward,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_FIRST,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook		= fortress_nf_out,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP6_PRI_FIRST,
	},
	{
		.hook		= fortress_nf_out,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP6_PRI_LAST,
	},
	{
		.hook		= fortress_nf_forward,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP6_PRI_FIRST,
	},
#endif
};

static int __net_init fortress_net_init(struct net *net)
{
	int err = nf_register_net_hooks(net, fortress_nf_ops,
					ARRAY_SIZE(fortress_nf_ops));

	/* A namespace without the guard must not come into existence. */
	if (err)
		pr_err("netfilter hook registration failed: %d\n", err);
	return err;
}

static void __net_exit fortress_net_exit(struct net *net)
{
	nf_unregister_net_hooks(net, fortress_nf_ops,
				ARRAY_SIZE(fortress_nf_ops));
}

static struct pernet_operations fortress_net_ops = {
	.init = fortress_net_init,
	.exit = fortress_net_exit,
};

int fortress_netguard_init(void)
{
	return register_pernet_subsys(&fortress_net_ops);
}
