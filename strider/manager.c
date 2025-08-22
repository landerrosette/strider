#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "manager.h"

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/string.h>
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

static struct strider_set *strider_set_lookup_locked(struct strider_net *sn, const char *name)
__must_hold(&sn->strider_sets_ht_lock) {
    u32 hash_key = jhash(name, strlen(name), 0);
    struct strider_set *set;
    hash_for_each_possible(sn->strider_sets_ht, set, node, hash_key) {
        if (strcmp(set->name, name) == 0)
            return set;
    }
    return NULL;
}

static int strider_set_refresh_ac_locked(struct strider_set *set) __must_hold(&set->lock) {
    int ret = 0;

    struct strider_ac *new_ac = strider_ac_init(GFP_KERNEL);
    if (IS_ERR(new_ac)) {
        ret = PTR_ERR(new_ac);
        goto out;
    }
    const struct strider_pattern *entry;
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

out:
    return ret;

fail:
    strider_ac_schedule_destroy(new_ac);
    goto out;
}

static void strider_sets_do_destroy_all_locked(struct strider_net *sn) __must_hold(&sn->strider_sets_ht_lock) {
    struct strider_set *set;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(sn->strider_sets_ht, bkt, tmp, set, node) {
        mutex_lock(&set->lock);
        hash_del(&set->node);

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

int __init strider_manager_init(void) {
    return register_pernet_subsys(&strider_net_ops);
}

void strider_manager_exit(void) {
    unregister_pernet_subsys(&strider_net_ops);
}

int strider_set_create(struct net *net, const char *name) {
    int ret = 0;

    if (!try_module_get(THIS_MODULE)) {
        ret = -ENODEV;
        goto out;
    }

    struct strider_set *new_set = kzalloc(sizeof(*new_set), GFP_KERNEL);
    if (!new_set) {
        ret = -ENOMEM;
        goto fail;
    }
    strscpy(new_set->name, name, STRIDER_MAX_SET_NAME_SIZE);
    INIT_LIST_HEAD(&new_set->patterns);
    mutex_init(&new_set->lock);
    refcount_set(&new_set->refcount, 0);

    struct strider_net *sn = strider_pernet(net);
    down_write(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, name);
    if (set) {
        ret = -EEXIST;
        goto fail_unlock_and_kfree;
    }
    hash_add(sn->strider_sets_ht, &new_set->node, jhash(name, strlen(name), 0));
    up_write(&sn->strider_sets_ht_lock);

out:
    return ret;

fail_unlock_and_kfree:
    up_write(&sn->strider_sets_ht_lock);
    kfree(new_set);
fail:
    module_put(THIS_MODULE);
    goto out;
}

int strider_set_destroy(struct net *net, const char *name) {
    struct strider_net *sn = strider_pernet(net);
    down_write(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, name);
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
    int ret = 0;

    struct strider_pattern *new_entry = kmalloc(struct_size(new_entry, data, len), GFP_KERNEL);
    if (!new_entry) {
        ret = -ENOMEM;
        goto out;
    }
    memcpy(new_entry->data, pattern, len);
    new_entry->len = len;

    struct strider_net *sn = strider_pernet(net);
    down_read(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, set_name);
    if (!set) {
        ret = -ENOENT;
        goto fail_sets_ht_unlock;
    }
    mutex_lock(&set->lock);
    up_read(&sn->strider_sets_ht_lock);

    const struct strider_pattern *entry;
    list_for_each_entry(entry, &set->patterns, list) {
        if (entry->len == len && memcmp(entry->data, pattern, len) == 0) {
            ret = -EEXIST;
            goto fail_set_unlock;
        }
    }
    list_add(&new_entry->list, &set->patterns);
    ret = strider_set_refresh_ac_locked(set);
    if (ret < 0)
        goto fail_list_del;
    mutex_unlock(&set->lock);

out:
    return ret;

fail_list_del:
    list_del(&new_entry->list);
fail_set_unlock:
    mutex_unlock(&set->lock);
    goto fail;
fail_sets_ht_unlock:
    up_read(&sn->strider_sets_ht_lock);
fail:
    kfree(new_entry);
    goto out;
}

int strider_set_del_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len) {
    int ret = 0;

    struct strider_net *sn = strider_pernet(net);
    down_read(&sn->strider_sets_ht_lock);
    struct strider_set *set = strider_set_lookup_locked(sn, set_name);
    if (!set) {
        ret = -ENOENT;
        goto fail;
    }
    mutex_lock(&set->lock);
    up_read(&sn->strider_sets_ht_lock);

    ret = -ENOENT;
    struct strider_pattern *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &set->patterns, list) {
        if (entry->len == len && memcmp(entry->data, pattern, len) == 0) {
            list_del(&entry->list);
            ret = strider_set_refresh_ac_locked(set);
            if (ret < 0)
                goto fail_list_add;
            kfree(entry);
            break;
        }
    }
    mutex_unlock(&set->lock);

out:
    return ret;

fail_list_add:
    list_add(&entry->list, &set->patterns);
    mutex_unlock(&set->lock);
    goto out;
fail:
    up_read(&sn->strider_sets_ht_lock);
    goto out;
}
