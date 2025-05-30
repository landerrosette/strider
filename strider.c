#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

unsigned int strider_nf_hookfn(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state) {
    pr_info("strider_nf_hookfn\n");
    return NF_ACCEPT;
}

static struct nf_hook_ops strider_nf_ops = {
    .hook = strider_nf_hookfn,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init strider_init(void) {
    int ret = nf_register_net_hook(&init_net, &strider_nf_ops);
    if (ret < 0) {
        pr_err("nf_register_net_hook failed\n");
        return ret;
    }
    return 0;
}

static void __exit strider_exit(void) {
    nf_unregister_net_hook(&init_net, &strider_nf_ops);
}

module_init(strider_init);
module_exit(strider_exit);

MODULE_LICENSE("Dual MIT/GPL");
