#include "strider_manager.h"

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <strider/defs.h>
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

static struct strider_set * __cold strider_set_lookup_locked(const char *name) __must_hold(&strider_sets_ht_lock) {
    u32 hash_key = jhash(name, strlen(name), 0);
    struct strider_set *set;
    hash_for_each_possible(strider_sets_ht, set, node, hash_key) {
        if (strcmp(set->name, name) == 0)
            return set;
    }
    return NULL;
}

static int __cold strider_set_rebuild_automaton_locked(struct strider_set *set) __must_hold(&set->lock) {
    size_t num_patterns = 0;
    const struct strider_pattern_entry *entry;
    list_for_each_entry(entry, &set->patterns, list)
        ++num_patterns;
    const char **patterns_array = kvmalloc_array(num_patterns, sizeof(*patterns_array), GFP_KERNEL);
    if (!patterns_array)
        return -ENOMEM;
    size_t i = 0;
    list_for_each_entry(entry, &set->patterns, list)
        patterns_array[i++] = entry->pattern;

    struct strider_ac_automaton *new_automaton = strider_ac_automaton_compile(patterns_array, num_patterns);
    kvfree(patterns_array);
    if (IS_ERR(new_automaton))
        return PTR_ERR(new_automaton);
    struct strider_ac_automaton *old_automaton = rcu_replace_pointer(set->automaton, new_automaton, lockdep_is_held(&set->lock));
    if (old_automaton)
        strider_ac_automaton_destroy_rcu(old_automaton);

    return 0;
}

static void __cold strider_set_deinit_locked(struct strider_set *set) __must_hold(&set->lock) {
    struct strider_pattern_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &set->patterns, list) {
        list_del(&entry->list);
        kfree(entry);
    }

    struct strider_ac_automaton *automaton = rcu_dereference_protected(set->automaton, lockdep_is_held(&set->lock));
    if (automaton)
        strider_ac_automaton_destroy_rcu(automaton);
}

int __init strider_manager_init(void) {
    // Nothing to do here as the hash table is statically initialized.
    return 0;
}

void __cold strider_manager_cleanup(void) {
    mutex_lock(&strider_sets_ht_lock);
    struct strider_set *set;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(strider_sets_ht, bkt, tmp, set, node) {
        mutex_lock(&set->lock);
        hash_del_rcu(&set->node);
        strider_set_deinit_locked(set);
        mutex_unlock(&set->lock);
        kfree_rcu(set, rcu);
    }
    mutex_unlock(&strider_sets_ht_lock);
    rcu_barrier();
}

int __cold strider_set_create(const char *name) {
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

int __cold strider_set_destroy(const char *name) {
    mutex_lock(&strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(name);
    if (!set) {
        mutex_unlock(&strider_sets_ht_lock);
        return -ENOENT;
    }
    mutex_lock(&set->lock);
    hash_del_rcu(&set->node);
    mutex_unlock(&strider_sets_ht_lock);
    strider_set_deinit_locked(set);
    mutex_unlock(&set->lock);
    kfree_rcu(set, rcu);
    return 0;
}

int __cold strider_set_add_pattern(const char *set_name, const char *pattern) {
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

int __cold strider_set_del_pattern(const char *set_name, const char *pattern) {
    int ret = 0;

    mutex_lock(&strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(set_name);
    if (!set) {
        ret = -ENOENT;
        goto fail;
    }
    mutex_lock(&set->lock);
    mutex_unlock(&strider_sets_ht_lock);
    ret = -ENOENT;
    struct strider_pattern_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &set->patterns, list) {
        if (strcmp(entry->pattern, pattern) == 0) {
            list_del(&entry->list);
            ret = strider_set_rebuild_automaton_locked(set);
            if (ret < 0) {
                // rollback
                list_add(&entry->list, &set->patterns);
                goto fail_set_unlock;
            }
            kfree(entry);
            break;
        }
    }
    mutex_unlock(&set->lock);

out:
    return ret;

fail_set_unlock:
    mutex_unlock(&set->lock);
    goto out;
fail:
    mutex_unlock(&strider_sets_ht_lock);
    goto out;
}

const struct strider_set *strider_set_lookup_rcu(const char *name) {
    u32 hash_key = jhash(name, strlen(name), 0);
    const struct strider_set *set;
    hash_for_each_possible_rcu(strider_sets_ht, set, node, hash_key) {
        if (strcmp(set->name, name) == 0)
            return set;
    }
    return NULL;
}

const struct strider_ac_automaton *strider_get_automaton(const struct strider_set *set) {
    return rcu_dereference(set->automaton);
}
