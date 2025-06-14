#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "matching.h"

#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <strider/defs.h>

#define STRIDER_VERDICT_HIGHEST_PRECEDENCE 0
#define STRIDER_VERDICT_LOWEST_PRECEDENCE INT_MAX

struct strider_rule {
    struct list_head list;

    u8 action;
    char pattern[]; // flexible array member
};

static LIST_HEAD(strider_rules_list);
static __cacheline_aligned_in_smp DEFINE_MUTEX(strider_rules_list_lock); // lock to protect write access

// This function acts as a central policy decision point for rule precedence.
// By encapsulating this logic, it allows for future extensions, such as configurable precedence.
// A lower return value signifies a higher precedence.
static inline __attribute_const__ int get_verdict_precedence(enum strider_verdict verdict) {
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

int __init strider_matching_init(void) {
    // The list head and mutex are statically initialized.
    // Nothing to do here for now.
    return 0;
}

void __init strider_matching_exit(void) {
    mutex_lock(&strider_rules_list_lock);

    struct strider_rule *rule, *tmp;
    list_for_each_entry_safe(rule, tmp, &strider_rules_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }

    mutex_unlock(&strider_rules_list_lock);
}

int strider_matching_add_rule(const char *pattern, u8 action) {
    int ret;

    mutex_lock(&strider_rules_list_lock);

    struct strider_rule *rule;
    // check if the rule already exists
    list_for_each_entry(rule, &strider_rules_list, list) {
        if (strcmp(rule->pattern, pattern) == 0 && rule->action == action) {
            ret = -EEXIST;
            goto out_unlock;
        }
    }

    rule = kmalloc(sizeof(*rule) + strlen(pattern) + 1, GFP_KERNEL);
    if (!rule) {
        ret = -ENOMEM;
        goto out_unlock;
    }
    strscpy(rule->pattern, pattern, strlen(pattern) + 1);
    rule->action = action;

    list_add(&rule->list, &strider_rules_list);

    ret = 0;

out_unlock:
    mutex_unlock(&strider_rules_list_lock);
    return ret;
}

int strider_matching_del_rule(const char *pattern, u8 action) {
    int ret = -ENOENT;

    mutex_lock(&strider_rules_list_lock);

    struct strider_rule *rule, *tmp;
    list_for_each_entry_safe(rule, tmp, &strider_rules_list, list) {
        if (strcmp(rule->pattern, pattern) == 0 && rule->action == action) {
            list_del(&rule->list);
            kfree(rule);
            ret = 0;
            break;
        }
    }

    mutex_unlock(&strider_rules_list_lock);

    return ret;
}

enum strider_verdict strider_matching_get_verdict(const char *payload, size_t len) {
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
