#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "core.h"

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/rwsem.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <strider/limits.h>

#include "ac.h"

#define STRIDER_SETS_HASH_BITS 4

struct strider_net {
    DECLARE_HASHTABLE(strider_sets_ht, STRIDER_SETS_HASH_BITS);
    struct rw_semaphore strider_sets_ht_lock;
};

static unsigned int strider_net_id __read_mostly;

static struct strider_net *strider_pernet(struct net *net) {
    return net_generic(net, strider_net_id);
}

static void strider_set_deinit_locked(struct strider_set *set) __must_hold(&set->lock) {
    struct strider_pattern *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &set->patterns, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    struct strider_ac *ac = rcu_dereference_protected(set->ac, lockdep_is_held(&set->lock));
    if (ac)
        strider_ac_schedule_destroy(ac);
}

static struct strider_set *strider_set_lookup_locked(struct strider_net *sn, const char *set_name)
__must_hold(&sn->strider_sets_ht_lock) {
    u32 hash_key = jhash(set_name, strlen(set_name), 0);
    struct strider_set *set;
    hash_for_each_possible(sn->strider_sets_ht, set, node, hash_key) {
        if (strcmp(set->name, set_name) == 0)
            return set;
    }
    return NULL;
}

static int strider_set_refresh_ac_locked(struct strider_set *set) __must_hold(&set->lock) {
    struct strider_ac *new_ac = strider_ac_init(GFP_KERNEL);
    if (IS_ERR(new_ac))
        return PTR_ERR(new_ac);
    const struct strider_pattern *entry;
    int ret = 0;
    list_for_each_entry(entry, &set->patterns, list) {
        ret = strider_ac_add_pattern(new_ac, entry->data, entry->len, GFP_KERNEL);
        if (ret < 0)
            goto fail;
    }
    ret = strider_ac_compile(new_ac, GFP_KERNEL);
    if (ret < 0)
        goto fail;
    struct strider_ac *old_ac = rcu_replace_pointer(set->ac, new_ac, lockdep_is_held(&set->lock));
    if (old_ac)
        strider_ac_schedule_destroy(old_ac);

    return ret;

fail:
    strider_ac_schedule_destroy(new_ac);
    return ret;
}

static void strider_sets_do_destroy_all_locked(struct strider_net *sn) __must_hold(&sn->strider_sets_ht_lock) {
    struct strider_set *set;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(sn->strider_sets_ht, bkt, tmp, set, node) {
        mutex_lock(&set->lock);
        hash_del(&set->node);

        pr_debug("set '%s' being destroyed, refcount=%u\n", set->name, refcount_read(&set->refcount));
        strider_set_deinit_locked(set);
        mutex_unlock(&set->lock);
        kfree(set);
    }
}

static int __net_init strider_net_init(struct net *net) {
    struct strider_net *sn = strider_pernet(net);
    hash_init(sn->strider_sets_ht);
    init_rwsem(&sn->strider_sets_ht_lock);
    return 0;
}

static void __net_exit strider_net_exit(struct net *net) {
    struct strider_net *sn = strider_pernet(net);
    down_write(&sn->strider_sets_ht_lock);
    strider_sets_do_destroy_all_locked(sn);
    up_write(&sn->strider_sets_ht_lock);
}

static struct pernet_operations strider_net_ops = {
    .init = strider_net_init,
    .exit = strider_net_exit,
    .id = &strider_net_id,
    .size = sizeof(struct strider_net),
};

int __init strider_core_init(void) {
    return register_pernet_subsys(&strider_net_ops);
}

void strider_core_exit(void) {
    unregister_pernet_subsys(&strider_net_ops);
    rcu_barrier();
}

int strider_set_create(struct net *net, const char *set_name) {
    if (!try_module_get(THIS_MODULE))
        return -ENODEV;

    int ret = 0;
    struct strider_set *new_set = kzalloc(sizeof(*new_set), GFP_KERNEL);
    if (!new_set) {
        ret = -ENOMEM;
        goto fail;
    }
    strscpy(new_set->name, set_name, STRIDER_MAX_SET_NAME_SIZE);
    INIT_LIST_HEAD(&new_set->patterns);
    mutex_init(&new_set->lock);
    refcount_set(&new_set->refcount, 0);

    struct strider_net *sn = strider_pernet(net);
    down_write(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, new_set->name);
    if (set) {
        ret = -EEXIST;
        goto fail_unlock;
    }
    hash_add(sn->strider_sets_ht, &new_set->node, jhash(new_set->name, strlen(new_set->name), 0));
    up_write(&sn->strider_sets_ht_lock);

    return ret;

fail_unlock:
    up_write(&sn->strider_sets_ht_lock);
    kfree(new_set);
fail:
    module_put(THIS_MODULE);
    return ret;
}

int strider_set_destroy(struct net *net, const char *set_name) {
    struct strider_net *sn = strider_pernet(net);
    down_write(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, set_name);
    if (!set) {
        up_write(&sn->strider_sets_ht_lock);
        return -ENOENT;
    }
    if (refcount_read(&set->refcount) > 0) {
        up_write(&sn->strider_sets_ht_lock);
        return -EBUSY;
    }
    mutex_lock(&set->lock);
    hash_del(&set->node);
    up_write(&sn->strider_sets_ht_lock);

    strider_set_deinit_locked(set);
    mutex_unlock(&set->lock);
    kfree(set);

    module_put(THIS_MODULE);

    return 0;
}

int strider_set_add_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len) {
    struct strider_pattern *new_entry = kmalloc(struct_size(new_entry, data, len), GFP_KERNEL);
    if (!new_entry)
        return -ENOMEM;
    memcpy(new_entry->data, pattern, len);
    new_entry->len = len;

    struct strider_net *sn = strider_pernet(net);
    down_read(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, set_name);
    if (!set) {
        up_read(&sn->strider_sets_ht_lock);
        return -ENOENT;
    }
    mutex_lock(&set->lock);
    up_read(&sn->strider_sets_ht_lock);

    const struct strider_pattern *entry;
    int ret = 0;
    list_for_each_entry(entry, &set->patterns, list) {
        if (entry->len == len && memcmp(entry->data, pattern, len) == 0) {
            ret = -EEXIST;
            goto fail;
        }
    }
    list_add(&new_entry->list, &set->patterns);
    ret = strider_set_refresh_ac_locked(set);
    if (ret < 0)
        goto fail_list_del;
    pr_debug("set '%s': added pattern len=%zu data=%*ph\n", set->name, new_entry->len, (int) new_entry->len,
             new_entry->data);
    mutex_unlock(&set->lock);

    return ret;

fail_list_del:
    list_del(&new_entry->list);
fail:
    mutex_unlock(&set->lock);
    kfree(new_entry);
    return ret;
}

int strider_set_del_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len) {
    struct strider_net *sn = strider_pernet(net);
    down_read(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, set_name);
    if (!set) {
        up_read(&sn->strider_sets_ht_lock);
        return -ENOENT;
    }
    mutex_lock(&set->lock);
    up_read(&sn->strider_sets_ht_lock);

    struct strider_pattern *entry, *tmp;
    int ret = -ENOENT;
    list_for_each_entry_safe(entry, tmp, &set->patterns, list) {
        if (entry->len == len && memcmp(entry->data, pattern, len) == 0) {
            list_del(&entry->list);
            ret = strider_set_refresh_ac_locked(set);
            if (ret < 0)
                goto fail;
            kfree(entry);
            break;
        }
    }
    mutex_unlock(&set->lock);

    return ret;

fail:
    list_add(&entry->list, &set->patterns);
    mutex_unlock(&set->lock);
    return ret;
}

struct strider_set *strider_set_get(struct net *net, const char *set_name) {
    struct strider_net *sn = strider_pernet(net);
    down_read(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, set_name);
    if (set)
        refcount_inc(&set->refcount);
    up_read(&sn->strider_sets_ht_lock);
    return set;
}

EXPORT_SYMBOL_GPL(strider_set_get);

void strider_set_put(struct strider_set *set) {
    if (set)
        refcount_dec(&set->refcount);
}

EXPORT_SYMBOL_GPL(strider_set_put);

bool strider_set_match(const struct strider_set *set, const struct sk_buff *skb, unsigned int offset,
                       unsigned int len) {
    rcu_read_lock();
    struct strider_ac *ac = rcu_dereference(set->ac);
    bool ret = false;
    if (unlikely(!ac))
        goto out;

    struct skb_seq_state skb_state;
    skb_prepare_seq_read((struct sk_buff *) skb, offset, offset + len, &skb_state);
    struct strider_ac_match_state ac_state;
    strider_ac_match_init(ac, &ac_state);
    const u8 *frag;
    for (unsigned int consumed = 0, frag_len; (frag_len = skb_seq_read(consumed, &frag, &skb_state)) > 0;
         consumed += frag_len) {
        ret = strider_ac_match_next(&ac_state, frag, frag_len);
        if (ret) {
            skb_abort_seq_read(&skb_state);
            break;
        }
    }

out:
    rcu_read_unlock();
    return ret;
}

EXPORT_SYMBOL_GPL(strider_set_match);
