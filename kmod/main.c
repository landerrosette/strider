#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>

#include "control.h"
#include "matching.h"

static unsigned int strider_nf_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (!skb) return NF_ACCEPT;

    struct iphdr *iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    if (ip_is_fragment(iph)) {
        // receiving a fragment at this point is unusual
        pr_warn_ratelimited("Ignoring fragmented packet");
        return NF_ACCEPT;
    }

    unsigned int ip_hdr_len = iph->ihl * 4;

    const char *payload = NULL;
    size_t payload_len = 0;

    if (iph->protocol == IPPROTO_TCP) {
        // ensure the TCP header is available and contiguous in memory
        if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
            return NF_ACCEPT;

        iph = ip_hdr(skb); // re-fetch IP header because pskb_may_pull() may have reallocated memory
        // The TCP header location must be calculated manually.
        // The helper tcp_hdr(skb) cannot be used here
        // because skb->transport_header is not guaranteed to be set at the NF_INET_PRE_ROUTING hook.
        struct tcphdr *tcph = (struct tcphdr *) ((const __u8 *) iph + ip_hdr_len);
        unsigned int tcp_hdr_len = tcph->doff * 4;

        // Validate the TCP header length itself,
        // then ensure the combined IP/TCP headers do not exceed the total packet length.
        // This prevents parsing malformed packets.
        if (tcp_hdr_len < sizeof(struct tcphdr))
            return NF_ACCEPT;
        if (ip_hdr_len + tcp_hdr_len > ntohs(iph->tot_len))
            return NF_ACCEPT;

        payload = (const char *) tcph + tcp_hdr_len;
        payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;
    } else if (iph->protocol == IPPROTO_UDP) {
        if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct udphdr)))
            return NF_ACCEPT;

        iph = ip_hdr(skb);
        struct udphdr *udph = (struct udphdr *) ((const __u8 *) iph + ip_hdr_len);

        if (ip_hdr_len + sizeof(struct udphdr) > ntohs(iph->tot_len))
            return NF_ACCEPT;

        payload = (const char *) udph + sizeof(struct udphdr);
        payload_len = ntohs(udph->len) - sizeof(struct udphdr);
    }

    if (payload_len == 0) return NF_ACCEPT;

    enum strider_verdict verdict = strider_matching_get_verdict(payload, payload_len);
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
    if (ret < 0) goto out;

    ret = strider_matching_init();
    if (ret < 0) goto out_control_exit;

    ret = nf_register_net_hook(&init_net, &strider_nf_ops);
    if (ret < 0) {
        pr_err("Failed to register netfilter hook: %d\n", ret);
        goto out_matching_exit;
    }

    pr_info("Module loaded\n");
    return 0;

out_matching_exit:
    strider_matching_exit();
out_control_exit:
    strider_control_exit();
out:
    return ret;
}

static void __exit strider_module_exit(void) {
    nf_unregister_net_hook(&init_net, &strider_nf_ops);
    strider_matching_exit();
    strider_control_exit();
    pr_info("Module unloaded\n");
}

module_init(strider_module_init);
module_exit(strider_module_exit);

MODULE_INFO(depends, "nf_conntrack");
MODULE_LICENSE("Dual MIT/GPL");
