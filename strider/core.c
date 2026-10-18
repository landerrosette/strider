// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2025-2026  landerrosette <57791410+landerrosette@users.noreply.github.com>
 */

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
#include <linux/mutex.h>
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
#include <strider/strider.h>
#include <strider/uapi/limits.h>

#include "ac.h"

#define STRIDER_SETS_HASH_BITS 4

struct strider_set {
	struct strider_ac __rcu *ac;
	struct mutex lock;
	struct list_head patterns;
	struct hlist_node list;
	refcount_t refcount;
	char name[STRIDER_MAX_SET_NAME_SIZE];
};

struct strider_pattern {
	struct list_head list;
	struct strider_ac_target ac_target;
	u8 data[];
};

struct strider_pattern_iter_ctx {
	struct list_head *head;
	struct list_head *pos;
};

struct strider_net {
	struct rw_semaphore strider_sets_ht_lock;
	DECLARE_HASHTABLE(strider_sets_ht, STRIDER_SETS_HASH_BITS);
};

static unsigned int strider_net_id __read_mostly;

static struct strider_net *strider_pernet(struct net *net)
{
	return net_generic(net, strider_net_id);
}

static void strider_set_destroy(struct strider_set *set)
{
	struct strider_pattern *entry, *tmp;

	pr_debug("set '%s': destroying\n", set->name);
	list_for_each_entry_safe(entry, tmp, &set->patterns, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	strider_ac_destroy_rcu(rcu_dereference_protected(set->ac, 1));
	kfree(set);
	module_put(THIS_MODULE);
}

static struct strider_set *strider_set_lookup_locked(struct strider_net *sn, const char *set_name)
	__must_hold(&sn->strider_sets_ht_lock)
{
	u32 hash_key = jhash(set_name, strlen(set_name), 0);
	struct strider_set *set;

	hash_for_each_possible(sn->strider_sets_ht, set, list, hash_key) {
		if (strcmp(set->name, set_name) == 0)
			return set;
	}
	return NULL;
}

static const struct strider_ac_target *strider_pattern_get_target(void *ctx)
{
	struct strider_pattern_iter_ctx *iter_ctx = ctx;
	const struct strider_ac_target *ret;

	if (list_is_head(iter_ctx->pos, iter_ctx->head))
		return NULL;
	ret = &list_entry(iter_ctx->pos, struct strider_pattern, list)->ac_target;
	iter_ctx->pos = iter_ctx->pos->next;
	return ret;
}

static int strider_set_refresh_ac_locked(struct strider_set *set) __must_hold(&set->lock)
{
	struct strider_ac *new_ac = NULL;
	struct strider_ac *old_ac;

	if (!list_empty(&set->patterns)) {
		struct strider_pattern_iter_ctx iter_ctx = { &set->patterns, set->patterns.next };

		new_ac = strider_ac_build(strider_pattern_get_target, &iter_ctx);
		if (IS_ERR(new_ac))
			return PTR_ERR(new_ac);
	}
	old_ac = rcu_replace_pointer(set->ac, new_ac, lockdep_is_held(&set->lock));
	strider_ac_destroy_rcu(old_ac);
	return 0;
}

static int __net_init strider_net_init(struct net *net)
{
	struct strider_net *sn = strider_pernet(net);

	hash_init(sn->strider_sets_ht);
	init_rwsem(&sn->strider_sets_ht_lock);
	return 0;
}

static void __net_exit strider_net_exit(struct net *net)
{
	struct strider_net *sn = strider_pernet(net);
	HLIST_HEAD(dispose_list);
	struct strider_set *set;
	struct hlist_node *tmp;
	int bkt;

	down_write(&sn->strider_sets_ht_lock);
	hash_for_each_safe(sn->strider_sets_ht, bkt, tmp, set, list) {
		hash_del(&set->list);
		hlist_add_head(&set->list, &dispose_list);
	}
	up_write(&sn->strider_sets_ht_lock);
	hlist_for_each_entry_safe(set, tmp, &dispose_list, list)
		strider_set_put(set);
}

static struct pernet_operations strider_net_ops __read_mostly = {
	.init = strider_net_init,
	.exit = strider_net_exit,
	.id = &strider_net_id,
	.size = sizeof(struct strider_net),
};

int __init strider_core_init(void)
{
	return register_pernet_subsys(&strider_net_ops);
}

void strider_core_exit(void)
{
	unregister_pernet_subsys(&strider_net_ops);
	rcu_barrier();
}

int strider_set_create(struct net *net, const char *set_name)
{
	struct strider_net *sn = strider_pernet(net);
	struct strider_set *new_set;
	int ret;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	new_set = kzalloc(sizeof(*new_set), GFP_KERNEL);
	if (!new_set) {
		ret = -ENOMEM;
		goto err_put;
	}
	strscpy(new_set->name, set_name, STRIDER_MAX_SET_NAME_SIZE);
	mutex_init(&new_set->lock);
	INIT_LIST_HEAD(&new_set->patterns);
	refcount_set(&new_set->refcount, 1);

	down_write(&sn->strider_sets_ht_lock);
	if (strider_set_lookup_locked(sn, new_set->name)) {
		ret = -EEXIST;
		goto err_unlock;
	}
	hash_add(sn->strider_sets_ht, &new_set->list,
		 jhash(new_set->name, strlen(new_set->name), 0));
	up_write(&sn->strider_sets_ht_lock);
	pr_debug("set '%s': created\n", new_set->name);
	return 0;

err_unlock:
	up_write(&sn->strider_sets_ht_lock);
	kfree(new_set);
err_put:
	module_put(THIS_MODULE);
	return ret;
}

int strider_set_remove(struct net *net, const char *set_name)
{
	struct strider_net *sn = strider_pernet(net);
	struct strider_set *set;
	int ret;

	down_write(&sn->strider_sets_ht_lock);
	set = strider_set_lookup_locked(sn, set_name);
	if (!set) {
		ret = -ENOENT;
		goto err_unlock;
	}
	if (refcount_read(&set->refcount) > 1) {
		ret = -EBUSY;
		goto err_unlock;
	}
	hash_del(&set->list);
	up_write(&sn->strider_sets_ht_lock);
	pr_debug("set '%s': removed\n", set->name);
	strider_set_put(set);
	return 0;

err_unlock:
	up_write(&sn->strider_sets_ht_lock);
	return ret;
}

int strider_set_add_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len)
{
	struct strider_pattern *new_entry;
	const struct strider_pattern *entry;
	struct strider_set *set;
	int ret;

	set = strider_set_get(net, set_name);
	if (IS_ERR(set))
		return PTR_ERR(set);
	new_entry = kmalloc(struct_size(new_entry, data, len), GFP_KERNEL);
	if (!new_entry) {
		ret = -ENOMEM;
		goto err_put;
	}
	memcpy(new_entry->data, pattern, len);
	new_entry->ac_target.pattern = new_entry->data;
	new_entry->ac_target.pattern_len = len;

	mutex_lock(&set->lock);
	list_for_each_entry(entry, &set->patterns, list) {
		if (entry->ac_target.pattern_len == len &&
		    memcmp(entry->ac_target.pattern, pattern, len) == 0) {
			ret = -EEXIST;
			goto err_unlock;
		}
	}
	list_add(&new_entry->list, &set->patterns);
	ret = strider_set_refresh_ac_locked(set);
	if (ret < 0)
		goto err_list_del;
	pr_debug("set '%s': added pattern len=%zu data=%*ph\n", set->name,
		 new_entry->ac_target.pattern_len, (int)new_entry->ac_target.pattern_len,
		 new_entry->data);
	mutex_unlock(&set->lock);
	strider_set_put(set);
	return 0;

err_list_del:
	list_del(&new_entry->list);
err_unlock:
	mutex_unlock(&set->lock);
	kfree(new_entry);
err_put:
	strider_set_put(set);
	return ret;
}

int strider_set_del_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len)
{
	struct strider_pattern *entry, *tmp;
	struct strider_set *set;
	int ret;

	set = strider_set_get(net, set_name);
	if (IS_ERR(set))
		return PTR_ERR(set);
	mutex_lock(&set->lock);
	ret = -ENOENT;
	list_for_each_entry_safe(entry, tmp, &set->patterns, list) {
		if (entry->ac_target.pattern_len == len &&
		    memcmp(entry->ac_target.pattern, pattern, len) == 0) {
			list_del(&entry->list);
			ret = strider_set_refresh_ac_locked(set);
			if (ret < 0) {
				list_add(&entry->list, &set->patterns);
				break;
			}
			kfree(entry);
			break;
		}
	}
	mutex_unlock(&set->lock);
	strider_set_put(set);
	return ret;
}

struct strider_set *strider_set_get(struct net *net, const char *set_name)
{
	struct strider_net *sn = strider_pernet(net);
	struct strider_set *set;

	down_read(&sn->strider_sets_ht_lock);
	set = strider_set_lookup_locked(sn, set_name);
	if (set) {
		pr_debug("set '%s': refcount=++%u\n", set->name, refcount_read(&set->refcount));
		refcount_inc(&set->refcount);
	}
	up_read(&sn->strider_sets_ht_lock);
	return set ? set : ERR_PTR(-ENOENT);
}
EXPORT_SYMBOL_GPL(strider_set_get);

void strider_set_put(struct strider_set *set)
{
	if (IS_ERR_OR_NULL(set))
		return;
	pr_debug("set '%s': refcount=--%u\n", set->name, refcount_read(&set->refcount));
	if (refcount_dec_and_test(&set->refcount))
		strider_set_destroy(set);
}
EXPORT_SYMBOL_GPL(strider_set_put);

static int strider_match_skb_cb(const struct strider_ac_target *target, size_t pos, void *ctx)
{
	*(bool *)ctx = true;
	return 1;
}

bool strider_match_skb(const struct strider_set *set, struct sk_buff *skb, unsigned int from,
		       unsigned int to)
{
	struct strider_ac_match_state ac_state;
	struct skb_seq_state skb_state;
	struct strider_ac *ac;
	const u8 *frag;
	bool ret = false;

	rcu_read_lock();
	ac = rcu_dereference(set->ac);
	if (unlikely(!ac))
		goto out;
	strider_ac_match_init(ac, &ac_state);
	skb_prepare_seq_read(skb, from, to, &skb_state);
	for (unsigned int consumed = 0, frag_len;
	     (frag_len = skb_seq_read(consumed, &frag, &skb_state)) > 0; consumed += frag_len) {
		strider_ac_match(&ac_state, frag, frag_len, strider_match_skb_cb, &ret);
		if (ret) {
			skb_abort_seq_read(&skb_state);
			break;
		}
	}
out:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(strider_match_skb);
