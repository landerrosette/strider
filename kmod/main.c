#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "matching.h"
#include "control.h"

static unsigned int strider_nf_hookfn(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    enum strider_verdict verdict = strider_matching_packet(skb);
    switch (verdict) {
        case STRIDER_VERDICT_DROP:
            return NF_DROP;
        case STRIDER_VERDICT_ACCEPT:
        case STRIDER_VERDICT_NOMATCH:
            return NF_ACCEPT;
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops strider_nf_ops = {
    .hook = strider_nf_hookfn,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1, // just after conntrack defragmentation
};

static int __init strider_module_init(void) {
    int ret;

    ret = strider_control_init();
    if (ret < 0) {
        pr_err("Failed to initialize control interface: %d\n", ret);
        goto out;
    }

    ret = strider_matching_init();
    if (ret < 0) {
        pr_err("Failed to initialize matching engine: %d\n", ret);
        goto out_nl_exit;
    }

    ret = nf_register_net_hook(&init_net, &strider_nf_ops);
    if (ret < 0) {
        pr_err("Failed to register netfilter hook: %d\n", ret);
        goto out_matching_exit;
    }

    return 0;

out_matching_exit:
    strider_matching_exit();
out_nl_exit:
    strider_control_exit();
out:
    return ret;
}

static void __exit strider_module_exit(void) {
    nf_unregister_net_hook(&init_net, &strider_nf_ops);
    strider_matching_exit();
    strider_control_exit();
}

module_init(strider_module_init);
module_exit(strider_module_exit);

MODULE_LICENSE("Dual MIT/GPL");
