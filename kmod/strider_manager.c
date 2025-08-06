#include "strider_manager.h"

// #include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
// #include <linux/limits.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <strider/defs.h>
#include <linux/vmalloc.h>
#include <linux/lockdep.h>
#include "strider_ac.h"

#define STRIDER_SETS_HASH_BITS 4

struct strider_pattern_entry {
    struct list_head list;
    char pattern[]; // flexible array member
};

struct strider_set {
    struct hlist_node node;
    char name[STRIDER_SET_NAME_MAX_LEN];
    struct list_head patterns; // list of strider_pattern_entry
    struct strider_ac_automaton __rcu *automaton;
    struct mutex lock;
    struct rcu_head rcu;
};

static DEFINE_HASHTABLE(strider_sets_ht, STRIDER_SETS_HASH_BITS);
static DEFINE_MUTEX(strider_sets_ht_lock); // lock to protect write access to the hash table

// MUST be called with strider_sets_ht_lock held
static struct strider_set *strider_set_lookup_locked(const char *name) {
    u32 hash_key = jhash(name, strlen(name), 0);
    struct strider_set *set;
    hash_for_each_possible(strider_sets_ht, set, node, hash_key) {
        if (strcmp(set->name, name) == 0)
            return set;
    }
    return NULL;
}

// MUST be called with set->lock held
static int strider_set_rebuild_automaton_locked(struct strider_set *set) {
    size_t num_patterns = 0;
    const struct strider_pattern_entry *entry;
    list_for_each_entry(entry, &set->patterns, list)
        ++num_patterns;

    const char **patterns_array = vmalloc(num_patterns * sizeof(*patterns_array));
    if (!patterns_array)
        return -ENOMEM;
    size_t i = 0;
    list_for_each_entry(entry, &set->patterns, list)
        patterns_array[i++] = entry->pattern;
    struct strider_ac_automaton *new_automaton = strider_ac_automaton_compile(patterns_array, num_patterns);
    vfree(patterns_array);
    if (IS_ERR(new_automaton))
        return PTR_ERR(new_automaton);

    struct strider_ac_automaton *old_automaton = rcu_replace_pointer(set->automaton, new_automaton, lockdep_is_held(&set->lock));
    if (old_automaton)
        strider_ac_automaton_destroy_rcu(old_automaton);

    return 0;
}

// // This function acts as a central policy decision point for rule precedence.
// // By encapsulating this logic, it allows for future extensions, such as configurable precedence.
// // A lower return value signifies a higher precedence.
// static __attribute_const__ int strider_get_verdict_precedence(enum strider_verdict verdict) {
//     switch (verdict) {
//         case STRIDER_VERDICT_DROP:
//             return STRIDER_VERDICT_HIGHEST_PRECEDENCE;
//         case STRIDER_VERDICT_ACCEPT:
//             return STRIDER_VERDICT_HIGHEST_PRECEDENCE + 1;
//         case STRIDER_VERDICT_NOMATCH:
//             return STRIDER_VERDICT_LOWEST_PRECEDENCE;
//     }
//     // should not reach here
//     WARN_ON_ONCE(1);
//     return STRIDER_VERDICT_LOWEST_PRECEDENCE;
// }

// static int strider_get_l4_payload_coords(const struct sk_buff *skb, size_t *offset, size_t *len) {
//     const struct iphdr *iph = ip_hdr(skb);
//     unsigned int ip_hdr_len = iph->ihl * 4;

//     if (unlikely(ip_hdr_len < sizeof(struct iphdr)))
//         return -EINVAL;

//     if (iph->protocol == IPPROTO_TCP) {
//         struct tcphdr _tcph;
//         const struct tcphdr *tcph = skb_header_pointer(skb, ip_hdr_len, sizeof(_tcph), &_tcph);
//         if (unlikely(!tcph))
//             return -EINVAL;
//         unsigned int tcp_hdr_len = tcph->doff * 4;

//         // TCP header length must be at least its minimum fixed size.
//         if (unlikely(tcp_hdr_len < sizeof(struct tcphdr)))
//             return -EINVAL;
//         // The combined IP and TCP header lengths must not exceed the total length of the IP datagram.
//         if (unlikely(ip_hdr_len + tcp_hdr_len > ntohs(iph->tot_len)))
//             return -EINVAL;

//         *offset = ip_hdr_len + tcp_hdr_len;
//         *len = ntohs(iph->tot_len) - *offset;
//     } else if (iph->protocol == IPPROTO_UDP) {
//         struct udphdr _udph;
//         const struct udphdr *udph = skb_header_pointer(skb, ip_hdr_len, sizeof(_udph), &_udph);
//         if (unlikely(!udph))
//             return -EINVAL;

//         // UDP length field must be at least the size of the header.
//         if (unlikely(ntohs(udph->len) < sizeof(struct udphdr)))
//             return -EINVAL;
//         // The UDP-claimed length must not exceed the available space calculated from the IP header.
//         if (unlikely(ntohs(udph->len) > ntohs(iph->tot_len) - ip_hdr_len))
//             return -EINVAL;

//         *offset = ip_hdr_len + sizeof(struct udphdr);
//         *len = ntohs(udph->len) - sizeof(struct udphdr);
//     } else {
//         return -EPROTONOSUPPORT;
//     }

//     if (unlikely(*offset > skb->len || *len > skb->len - *offset))
//         return -EINVAL;

//     return 0;
// }

int __init strider_manager_init(void) {
    // Nothing to do here as the hash table is statically initialized.
    return 0;
}

void strider_manager_cleanup(void) {
//     mutex_lock(&strider_rules_list_lock);

//     struct strider_rule *rule, *tmp;
//     list_for_each_entry_safe(rule, tmp, &strider_rules_list, list) {
//         list_del(&rule->list);
//         kfree(rule);
//     }

//     struct strider_ac_rcu *wrapper = rcu_replace_pointer(strider_ac_automaton, NULL,
//                                                          lockdep_is_held(&strider_rules_list_lock));
//     if (wrapper)
//         call_rcu(&wrapper->rcu, strider_ac_automaton_free_rcu_cb);

//     mutex_unlock(&strider_rules_list_lock);

//     rcu_barrier();
}

int strider_set_create(const char *name) {
    int ret = 0;

    struct strider_set *new_set = kzalloc(sizeof(*new_set), GFP_KERNEL);
    if (!new_set) {
        ret = -ENOMEM;
        goto out;
    }
    strscpy(new_set->name, name, STRIDER_SET_NAME_MAX_LEN);
    INIT_LIST_HEAD(&new_set->patterns);
    mutex_init(&new_set->lock);

    mutex_lock(&strider_sets_ht_lock);

    struct strider_set *set = strider_set_lookup_locked(name);
    if (set) {
        ret = -EEXIST;
        goto fail;
    }
    hash_add_rcu(strider_sets_ht, &new_set->node, jhash(name, strlen(name), 0));

out_unlock:
    mutex_unlock(&strider_sets_ht_lock);
out:
    return ret;

fail:
    kfree(new_set);
    goto out_unlock;
}

int strider_set_destroy(const char *name) {
    mutex_lock(&strider_sets_ht_lock);

    struct strider_set *set, *tmp;
    int ret = -ENOENT;
//     list_for_each_entry_safe(rule, tmp, &strider_rules_list, list) {
//         if (strcmp(rule->pattern, pattern) == 0 && rule->action == action) {
//             list_del(&rule->list);
//             ret = strider_ac_automaton_rebuild_locked();
//             if (ret < 0) {
//                 // rollback
//                 list_add(&rule->list, &strider_rules_list);
//                 goto out;
//             }
//             kfree(rule);
//             break;
//         }
//     }

out:
    mutex_unlock(&strider_sets_ht_lock);

    return ret;
}

int strider_set_add_pattern(const char *set_name, const char *pattern) {
    int ret = 0;

    struct strider_pattern_entry *new_entry = kmalloc(sizeof(*new_entry) + strlen(pattern) + 1, GFP_KERNEL);
    if (!new_entry) {
        ret = -ENOMEM;
        goto out;
    }
    strscpy(new_entry->pattern, pattern, strlen(pattern) + 1);

    mutex_lock(&strider_sets_ht_lock);

    struct strider_set *set = strider_set_lookup_locked(set_name);
    if (!set) {
        ret = -ENOENT;
        goto fail_sets_ht_unlock;
    }

    mutex_lock(&set->lock);
    mutex_unlock(&strider_sets_ht_lock);

    const struct strider_pattern_entry *entry;
    list_for_each_entry(entry, &set->patterns, list) {
        if (strcmp(entry->pattern, pattern) == 0) {
            ret = -EEXIST;
            goto fail_set_unlock;
        }
    }
    list_add(&new_entry->list, &set->patterns);

    ret = strider_set_rebuild_automaton_locked(set);
    if (ret < 0) {
        list_del(&new_entry->list);
        goto fail_set_unlock;
    }

    mutex_unlock(&set->lock);

out:
    return ret;

fail_set_unlock:
    mutex_unlock(&set->lock);
    goto fail;
fail_sets_ht_unlock:
    mutex_unlock(&strider_sets_ht_lock);
fail:
    kfree(new_entry);
    goto out;
}

// struct strider_match_ctx {
//     enum strider_verdict verdict;
// };

// static int strider_match_cb(const void *priv, size_t offset, void *cb_ctx) {
//     const struct strider_rule *rule = priv;
//     enum strider_verdict current_verdict = STRIDER_VERDICT_NOMATCH;
//     switch (rule->action) {
//         case STRIDER_ACTION_DROP:
//             current_verdict = STRIDER_VERDICT_DROP;
//             break;
//         case STRIDER_ACTION_ACCEPT:
//             current_verdict = STRIDER_VERDICT_ACCEPT;
//             break;
//         case STRIDER_ACTION_UNSPEC:
//             // should not happen
//             WARN_ON_ONCE(1);
//             break;
//     }

//     struct strider_match_ctx *ctx = cb_ctx;
//     if (strider_get_verdict_precedence(current_verdict) < strider_get_verdict_precedence(ctx->verdict))
//         ctx->verdict = current_verdict;

//     if (strider_get_verdict_precedence(ctx->verdict) == STRIDER_VERDICT_HIGHEST_PRECEDENCE)
//         return 1; // highest precedence verdict found, abort
//     return 0;     // continue matching
// }

// bool strider_matching_match_skb(const struct sk_buff *skb) {
//     rcu_read_lock();

//     struct strider_match_ctx match_ctx = {.verdict = STRIDER_VERDICT_NOMATCH};
//     const struct strider_ac_rcu *wrapper = rcu_dereference(strider_ac_automaton);
//     if (!wrapper)
//         goto out;
//     const struct strider_ac_automaton *automaton = wrapper->automaton;

//     size_t offset, len;
//     if (strider_get_l4_payload_coords(skb, &offset, &len) < 0 || len == 0) {
//         match_ctx.verdict = STRIDER_VERDICT_ACCEPT;
//         goto out;
//     }

//     struct skb_seq_state skb_state;
//     skb_prepare_seq_read((struct sk_buff *) skb, offset, offset + len, &skb_state);
//     struct strider_ac_match_state ac_state;
//     strider_ac_match_state_init(&ac_state, automaton);

//     const u8 *payload_frag;
//     unsigned int frag_len;
//     unsigned int consumed = 0;
//     while ((frag_len = skb_seq_read(consumed, &payload_frag, &skb_state)) > 0) {
//         int ret = strider_ac_automaton_feed(&ac_state, payload_frag, frag_len, strider_match_cb, &match_ctx);
//         consumed += frag_len;
//         if (ret != 0)
//             goto out_abort_read;
//     }

// out_abort_read:
//     skb_abort_seq_read(&skb_state);

// out:
//     rcu_read_unlock();

//     return match_ctx.verdict;
// }
