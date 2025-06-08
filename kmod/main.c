#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "netlink.h"

static unsigned int strider_nf_hookfn(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    return NF_ACCEPT;
}

static struct nf_hook_ops strider_nf_ops = {
    .hook = strider_nf_hookfn,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init strider_module_init(void) {
    int ret;

    ret = strider_nl_init();
    if (ret < 0) {
        pr_err("Failed to initialize netlink: %d\n", ret);
        goto out;
    }

    ret = nf_register_net_hook(&init_net, &strider_nf_ops);
    if (ret < 0) {
        pr_err("Failed to register netfilter hook: %d\n", ret);
        goto out_nl_exit;
    }

    return 0;

out_nl_exit:
    strider_nl_exit();
out:
    return ret;
}

static void __exit strider_module_exit(void) {
    nf_unregister_net_hook(&init_net, &strider_nf_ops);
    strider_nl_exit();
}

module_init(strider_module_init);
module_exit(strider_module_exit);

MODULE_LICENSE("Dual MIT/GPL");
