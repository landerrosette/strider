#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "rule.h"
#include "matchers.h"
#include "logging.h"

extern const struct wdum_rule* wdum_read_next_rule(unsigned int filter_type,
                                                   const struct wdum_rule* curr_rule);

static bool wdum_is_general(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    if (iph)
        return true;
    return false;
}

static bool wdum_is_http(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP)) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl << 2);
        if (ntohs(tcph->dest == 80) || ntohs(tcph->source) == 80)
            return true;
    }
    return false;
}

static bool wdum_is_dns(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    if (iph && iph->protocol && (iph->protocol == IPPROTO_UDP)) {
        struct udphdr *udph = (void *)iph + (iph->ihl << 2);
        if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53)
            return true;
    }
    return false;
}

static bool (*wdum_pre_check[WDUM_NUM_RULE_FILTER_TYPES])(struct sk_buff *skb) = {
    wdum_is_general,
    wdum_is_http,
    wdum_is_dns,
};

static unsigned int wdum_nf_hookfn(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state) {
    const struct wdum_rule *rule = NULL;
    int i;

    for (i = 0; i < WDUM_NUM_RULE_FILTER_TYPES; i++) {
        if (wdum_pre_check[i](skb)) {
            while ((rule = wdum_read_next_rule(i, rule))) {
                if (wdum_matchers[rule->pattern_type](rule, skb, 0, skb->len)) {
                    wdum_log_filter(rule->pattern, rule->pattern_type, i);
                    return NF_DROP;
                }
            }
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops wdum_nf_hook_ops[] __read_mostly = {
    {
        .hook = wdum_nf_hookfn,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = wdum_nf_hookfn,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
};

static int __init wdum_filter_init(void) {
    int retval;

    retval = nf_register_net_hooks(&init_net, wdum_nf_hook_ops, 2);
    if (retval < 0)
        wdum_log_error("registering netfilter hooks");

    return retval;
}

static void __exit wdum_filter_exit(void) {
    nf_unregister_net_hooks(&init_net, wdum_nf_hook_ops, 2);
}

MODULE_LICENSE("Dual BSD/GPL");

module_init(wdum_filter_init);
module_exit(wdum_filter_exit);
