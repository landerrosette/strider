#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <net/ip.h>

#include "control.h"
#include "matching.h"

static unsigned int strider_nf_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (unlikely(!skb)) return NF_ACCEPT;

    const struct iphdr *iph = ip_hdr(skb);
    if (unlikely(!iph)) return NF_ACCEPT;

    if (unlikely(ip_is_fragment(iph))) {
        // receiving a fragment at this point is unusual
        pr_warn_ratelimited("Ignoring fragmented packet\n");
        return NF_ACCEPT;
    }

    enum strider_verdict verdict = strider_matching_get_verdict(skb);
    switch (verdict) {
        case STRIDER_VERDICT_DROP:
            return NF_DROP;
        case STRIDER_VERDICT_ACCEPT:
        case STRIDER_VERDICT_NOMATCH:
            return NF_ACCEPT;
    }

    // should not reach here
    WARN_ON_ONCE(1);
    return NF_ACCEPT;
}

static const struct nf_hook_ops strider_nf_hook_ops = {
    .hook = strider_nf_hookfn,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1, // just after conntrack defragmentation
};

static int __init strider_module_init(void) {
    int ret = strider_control_init();
    if (ret < 0) goto out;

    ret = strider_matching_init();
    if (ret < 0) goto fail;

    ret = nf_register_net_hook(&init_net, &strider_nf_hook_ops);
    if (ret < 0) {
        pr_err("Failed to register netfilter hook: %d\n", ret);
        goto fail_matching_cleanup;
    }

    pr_info("Module loaded\n");

out:
    return ret;

fail_matching_cleanup:
    strider_matching_cleanup();
fail:
    strider_control_cleanup();
    goto out;
}

static void __exit strider_module_exit(void) {
    nf_unregister_net_hook(&init_net, &strider_nf_hook_ops);
    strider_matching_cleanup();
    strider_control_cleanup();
    pr_info("Module unloaded\n");
}

module_init(strider_module_init);
module_exit(strider_module_exit);

MODULE_INFO(depends, "nf_conntrack");
MODULE_LICENSE("Dual MIT/GPL");
