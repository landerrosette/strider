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

struct strider_ac_rcu {
    struct rcu_head rcu;
    struct strider_ac_automaton *automaton;
};

static LIST_HEAD(strider_rules_list);
static __cacheline_aligned_in_smp DEFINE_MUTEX(strider_rules_list_lock); // lock to protect write access
static struct strider_ac_rcu __rcu *strider_ac_automaton __read_mostly;

static void strider_ac_automaton_free_rcu_cb(struct rcu_head *head) {
    struct strider_ac_rcu *wrapper = container_of(head, struct strider_ac_rcu, rcu);
    strider_ac_automaton_free(wrapper->automaton);
    kfree(wrapper);
}

// MUST be called with strider_rules_list_lock held
static int strider_ac_automaton_rebuild_locked(void) {
    struct strider_ac_rcu *new_wrapper = kmalloc(sizeof(*new_wrapper), GFP_KERNEL);
    int ret = 0;
    if (!new_wrapper) {
        ret = -ENOMEM;
        goto out;
    }

    const struct strider_rule *rule;
    LIST_HEAD(inputs_head);
    list_for_each_entry(rule, &strider_rules_list, list) {
        struct strider_ac_input *input = kmalloc(sizeof(*input), GFP_KERNEL);
        if (!input) {
            ret = -ENOMEM;
            goto fail;
        }
        input->pattern = rule->pattern;
        input->len = strlen(rule->pattern);
        input->priv = rule;
        list_add_tail(&input->list, &inputs_head);
    }

    struct strider_ac_automaton *new_automaton = strider_ac_automaton_build(&inputs_head);
    if (IS_ERR(new_automaton)) {
        ret = PTR_ERR(new_automaton);
        goto fail;
    }
    new_wrapper->automaton = new_automaton;
    struct strider_ac_rcu *old_wrapper = rcu_replace_pointer(strider_ac_automaton, new_wrapper,
                                                             lockdep_is_held(&strider_rules_list_lock));
    if (old_wrapper) // if there was a previous automaton
        call_rcu(&old_wrapper->rcu, strider_ac_automaton_free_rcu_cb);

out_cleanup:
    struct strider_ac_input *input, *tmp;
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

// This function acts as a central policy decision point for rule precedence.
// By encapsulating this logic, it allows for future extensions, such as configurable precedence.
// A lower return value signifies a higher precedence.
static __attribute_const__ int strider_get_verdict_precedence(enum strider_verdict verdict) {
    switch (verdict) {
        case STRIDER_VERDICT_DROP:
            return STRIDER_VERDICT_HIGHEST_PRECEDENCE;
        case STRIDER_VERDICT_ACCEPT:
            return STRIDER_VERDICT_HIGHEST_PRECEDENCE + 1;
        case STRIDER_VERDICT_NOMATCH:
            return STRIDER_VERDICT_LOWEST_PRECEDENCE;
    }
    // should not reach here
    WARN_ON_ONCE(1);
    return STRIDER_VERDICT_LOWEST_PRECEDENCE;
}

static int strider_get_l4_payload_coords(const struct sk_buff *skb, size_t *offset, size_t *len) {
    const struct iphdr *iph = ip_hdr(skb);
    unsigned int ip_hdr_len = iph->ihl * 4;

    if (unlikely(ip_hdr_len < sizeof(struct iphdr)))
        return -EINVAL;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr _tcph;
        const struct tcphdr *tcph = skb_header_pointer(skb, ip_hdr_len, sizeof(_tcph), &_tcph);
        if (unlikely(!tcph))
            return -EINVAL;
        unsigned int tcp_hdr_len = tcph->doff * 4;

        // TCP header length must be at least its minimum fixed size.
        if (unlikely(tcp_hdr_len < sizeof(struct tcphdr)))
            return -EINVAL;
        // The combined IP and TCP header lengths must not exceed the total length of the IP datagram.
        if (unlikely(ip_hdr_len + tcp_hdr_len > ntohs(iph->tot_len)))
            return -EINVAL;

        *offset = ip_hdr_len + tcp_hdr_len;
        *len = ntohs(iph->tot_len) - *offset;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr _udph;
        const struct udphdr *udph = skb_header_pointer(skb, ip_hdr_len, sizeof(_udph), &_udph);
        if (unlikely(!udph))
            return -EINVAL;

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

    struct strider_ac_rcu *wrapper = rcu_replace_pointer(strider_ac_automaton, NULL,
                                                         lockdep_is_held(&strider_rules_list_lock));
    if (wrapper)
        call_rcu(&wrapper->rcu, strider_ac_automaton_free_rcu_cb);

    mutex_unlock(&strider_rules_list_lock);

    rcu_barrier();
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

struct strider_match_ctx {
    enum strider_verdict verdict;
};

static int strider_match_cb(const void *priv, size_t offset, void *cb_ctx) {
    const struct strider_rule *rule = priv;
    enum strider_verdict current_verdict = STRIDER_VERDICT_NOMATCH;
    switch (rule->action) {
        case STRIDER_ACTION_DROP:
            current_verdict = STRIDER_VERDICT_DROP;
            break;
        case STRIDER_ACTION_ACCEPT:
            current_verdict = STRIDER_VERDICT_ACCEPT;
            break;
        case STRIDER_ACTION_UNSPEC:
            // should not happen
            WARN_ON_ONCE(1);
            break;
    }

    struct strider_match_ctx *ctx = cb_ctx;
    if (strider_get_verdict_precedence(current_verdict) < strider_get_verdict_precedence(ctx->verdict))
        ctx->verdict = current_verdict;

    if (strider_get_verdict_precedence(ctx->verdict) == STRIDER_VERDICT_HIGHEST_PRECEDENCE)
        return 1; // highest precedence verdict found, abort
    return 0;     // continue matching
}

enum strider_verdict strider_matching_get_verdict(const struct sk_buff *skb) {
    rcu_read_lock();

    struct strider_match_ctx match_ctx = {.verdict = STRIDER_VERDICT_NOMATCH};
    const struct strider_ac_rcu *wrapper = rcu_dereference(strider_ac_automaton);
    if (!wrapper)
        goto out;
    const struct strider_ac_automaton *automaton = wrapper->automaton;

    size_t offset, len;
    if (strider_get_l4_payload_coords(skb, &offset, &len) < 0 || len == 0) {
        match_ctx.verdict = STRIDER_VERDICT_ACCEPT;
        goto out;
    }

    struct skb_seq_state skb_state;
    skb_prepare_seq_read((struct sk_buff *) skb, offset, offset + len, &skb_state);
    struct strider_ac_match_state ac_state;
    strider_ac_match_state_init(&ac_state, automaton);

    const u8 *payload_frag;
    unsigned int frag_len;
    unsigned int consumed = 0;
    while ((frag_len = skb_seq_read(consumed, &payload_frag, &skb_state)) > 0) {
        int ret = strider_ac_automaton_feed(&ac_state, payload_frag, frag_len, strider_match_cb, &match_ctx);
        consumed += frag_len;
        if (ret != 0)
            goto out_abort_read;
    }

out_abort_read:
    skb_abort_seq_read(&skb_state);

out:
    rcu_read_unlock();

    return match_ctx.verdict;
}
