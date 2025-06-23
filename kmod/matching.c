#include "matching.h"

#include <linux/cache.h>
#include <linux/compiler_attributes.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#include "aho_corasick.h"

#define STRIDER_VERDICT_HIGHEST_PRECEDENCE 0
#define STRIDER_VERDICT_LOWEST_PRECEDENCE INT_MAX

struct strider_rule {
    struct list_head list;
    enum strider_action action;
    char pattern[]; // flexible array member
};

struct strider_ac_automaton {
    struct rcu_head rcu;
    struct ac_automaton *automaton;
};

static LIST_HEAD(strider_rules_list);
static __cacheline_aligned_in_smp DEFINE_MUTEX(strider_rules_list_lock); // lock to protect write access
static struct strider_ac_automaton __rcu *strider_ac_automaton;

// This function acts as a central policy decision point for rule precedence.
// By encapsulating this logic, it allows for future extensions, such as configurable precedence.
// A lower return value signifies a higher precedence.
static __attribute_const__ int get_verdict_precedence(enum strider_verdict verdict) {
    switch (verdict) {
        case STRIDER_VERDICT_DROP:
            return STRIDER_VERDICT_HIGHEST_PRECEDENCE;
        case STRIDER_VERDICT_ACCEPT:
            return STRIDER_VERDICT_HIGHEST_PRECEDENCE + 1;
        case STRIDER_VERDICT_NOMATCH:
            return STRIDER_VERDICT_LOWEST_PRECEDENCE;
    }
    return STRIDER_VERDICT_LOWEST_PRECEDENCE; // should not happen
}

static int strider_get_l4_payload_coords(struct sk_buff *skb, size_t *offset, size_t *len) {
    const struct iphdr *iph = ip_hdr(skb);
    unsigned int ip_hdr_len = iph->ihl * 4;

    if (unlikely(ip_hdr_len < sizeof(struct iphdr)))
        return -EINVAL;

    if (iph->protocol == IPPROTO_TCP) {
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr))))
            return -EINVAL;

        iph = ip_hdr(skb);
        // The TCP header location must be calculated manually.
        // The helper tcp_hdr(skb) cannot be used here
        // because skb->transport_header is not guaranteed to be set at the NF_INET_PRE_ROUTING hook.
        const struct tcphdr *tcph = (const struct tcphdr *) ((const u8 *) iph + ip_hdr_len);
        unsigned int tcp_hdr_len = tcph->doff * 4;

        // TCP header length must be at least its minimum fixed size.
        if (unlikely(tcp_hdr_len < sizeof(struct tcphdr)))
            return -EINVAL;
        // The combined IP and TCP header lengths must not exceed the total length of the IP datagram.
        if (unlikely(ip_hdr_len + tcp_hdr_len > ntohs(iph->tot_len)))
            return -EINVAL;

        // If TCP options are present, pull the full header.
        if (tcp_hdr_len > sizeof(struct tcphdr)) {
            if (unlikely(!pskb_may_pull(skb, ip_hdr_len + tcp_hdr_len)))
                return -EINVAL;
            iph = ip_hdr(skb);
        }

        *offset = ip_hdr_len + tcp_hdr_len;
        *len = ntohs(iph->tot_len) - *offset;
    } else if (iph->protocol == IPPROTO_UDP) {
        if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct udphdr))))
            return -EINVAL;

        iph = ip_hdr(skb);
        const struct udphdr *udph = (const struct udphdr *) ((const u8 *) iph + ip_hdr_len);

        // UDP length field must be at least the size of the header.
        if (unlikely(ntohs(udph->len) < sizeof(struct udphdr)))
            return -EINVAL;
        // The UDP-claimed length must not exceed the available space calculated from the IP header.
        if (unlikely(ntohs(udph->len) > ntohs(iph->tot_len) - ip_hdr_len))
            return -EINVAL;

        *offset = ip_hdr_len + sizeof(struct udphdr);
        *len = ntohs(udph->len) - sizeof(struct udphdr);
    } else {
        return -EPROTONOSUPPORT;
    }

    if (unlikely(*offset > skb->len || *len > skb->len - *offset))
        return -EINVAL;

    return 0;
}

static void strider_ac_automaton_free_rcu_cb(struct rcu_head *head) {
    struct strider_ac_automaton *wrapper = container_of(head, struct strider_ac_automaton, rcu);
    ac_automaton_free(wrapper->automaton);
    kfree(wrapper);
}

// MUST be called with strider_rules_list_lock held
static int strider_ac_automaton_rebuild_locked(void) {
    struct strider_ac_automaton *new_wrapper = kmalloc(sizeof(*new_wrapper), GFP_KERNEL);
    int ret = 0;
    if (!new_wrapper) {
        ret = -ENOMEM;
        goto out;
    }

    struct strider_rule *rule;
    LIST_HEAD(inputs_head);
    list_for_each_entry(rule, &strider_rules_list, list) {
        struct ac_input *input = kmalloc(sizeof(*input), GFP_KERNEL);
        if (!input) {
            ret = -ENOMEM;
            goto fail;
        }
        input->pattern = rule->pattern;
        input->len = strlen(rule->pattern);
        input->priv = rule;
        list_add_tail(&input->list, &inputs_head);
    }

    struct ac_automaton *new_automaton = ac_automaton_build(&inputs_head);
    if (IS_ERR(new_automaton)) {
        ret = PTR_ERR(new_automaton);
        goto fail;
    }
    new_wrapper->automaton = new_automaton;
    struct strider_ac_automaton *old_wrapper = rcu_replace_pointer(strider_ac_automaton, new_wrapper,
                                                                   lockdep_is_held(&strider_rules_list_lock));
    if (old_wrapper) // if there was a previous automaton
        call_rcu(&old_wrapper->rcu, strider_ac_automaton_free_rcu_cb);

out_cleanup:
    struct ac_input *input, *tmp;
    list_for_each_entry_safe(input, tmp, &inputs_head, list) {
        list_del(&input->list);
        kfree(input);
    }
out:
    return ret;

fail:
    kfree(new_wrapper);
    goto out_cleanup;
}

int __init strider_matching_init(void) {
    // The list head and mutex are statically initialized.
    // Nothing to do here.
    return 0;
}

void strider_matching_cleanup(void) {
    mutex_lock(&strider_rules_list_lock);

    struct strider_rule *rule, *tmp;
    list_for_each_entry_safe(rule, tmp, &strider_rules_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }

    mutex_unlock(&strider_rules_list_lock);
}

int strider_matching_add_rule(const char *pattern, enum strider_action action) {
    mutex_lock(&strider_rules_list_lock);

    struct strider_rule *rule;
    int ret = 0;
    // check if the rule already exists
    list_for_each_entry(rule, &strider_rules_list, list) {
        if (strcmp(rule->pattern, pattern) == 0 && rule->action == action) {
            ret = -EEXIST;
            goto out;
        }
    }

    rule = kmalloc(sizeof(*rule) + strlen(pattern) + 1, GFP_KERNEL);
    if (!rule) {
        ret = -ENOMEM;
        goto out;
    }
    strscpy(rule->pattern, pattern, strlen(pattern) + 1);
    rule->action = action;
    list_add(&rule->list, &strider_rules_list);

    ret = strider_ac_automaton_rebuild_locked();
    if (ret < 0) {
        // rollback
        list_del(&rule->list);
        kfree(rule);
        goto out;
    }

out:
    mutex_unlock(&strider_rules_list_lock);

    return ret;
}

int strider_matching_del_rule(const char *pattern, enum strider_action action) {
    mutex_lock(&strider_rules_list_lock);

    struct strider_rule *rule, *tmp;
    int ret = -ENOENT;
    list_for_each_entry_safe(rule, tmp, &strider_rules_list, list) {
        if (strcmp(rule->pattern, pattern) == 0 && rule->action == action) {
            list_del(&rule->list);
            ret = strider_ac_automaton_rebuild_locked();
            if (ret < 0) {
                // rollback
                list_add(&rule->list, &strider_rules_list);
                goto out;
            }
            kfree(rule);
            break;
        }
    }

out:
    mutex_unlock(&strider_rules_list_lock);

    return ret;
}

enum strider_verdict strider_matching_get_verdict(struct sk_buff *skb) {
    enum strider_verdict final_verdict = STRIDER_VERDICT_NOMATCH;

    // rcu_read_lock();
    //
    // struct strider_rule *rule;
    // list_for_each_entry_rcu(rule, &strider_rules_list, list) {
    //     if (strnstr(payload, rule->pattern, len)) {
    //         enum strider_verdict current_verdict;
    //         switch (rule->action) {
    //             case STRIDER_ACTION_DROP:
    //                 current_verdict = STRIDER_VERDICT_DROP;
    //                 break;
    //             case STRIDER_ACTION_ACCEPT:
    //                 current_verdict = STRIDER_VERDICT_ACCEPT;
    //                 break;
    //             default:
    //                 continue;
    //         }
    //         if (get_verdict_precedence(current_verdict) < get_verdict_precedence(final_verdict))
    //             final_verdict = current_verdict;
    //         if (get_verdict_precedence(final_verdict) == STRIDER_VERDICT_HIGHEST_PRECEDENCE)
    //             break; // highest precedence reached, no need to check further
    //     }
    // }
    //
    // rcu_read_unlock();

    return final_verdict;
}
