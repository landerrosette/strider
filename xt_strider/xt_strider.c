// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2025-2026  landerrosette <57791410+landerrosette@users.noreply.github.com>
 */

#include "xt_strider.h"

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <strider/strider.h>
#include <strider/uapi/limits.h>

static bool strider_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_strider_info *info = par->matchinfo;
	bool invert = info->flags & XT_STRIDER_FLAG_INVERT;
	return strider_match_skb(info->set, (struct sk_buff *)skb, info->from_offset,
				 info->to_offset) ^
	       invert;
}

static int strider_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_strider_info *info = par->matchinfo;
	if (info->from_offset > info->to_offset)
		return -EINVAL;
	if (info->set_name[STRIDER_MAX_SET_NAME_SIZE - 1] != '\0')
		return -EINVAL;
	struct strider_set *set = strider_set_get(par->net, info->set_name);
	if (IS_ERR(set))
		return PTR_ERR(set);
	info->set = set;
	return 0;
}

static void strider_mt_destroy(const struct xt_mtdtor_param *par)
{
	strider_set_put(((struct xt_strider_info *)par->matchinfo)->set);
}

static struct xt_match xt_strider_mt_reg __read_mostly = {
	.name = "strider",
	.revision = 0,
	.family = NFPROTO_UNSPEC,
	.match = strider_mt,
	.checkentry = strider_mt_check,
	.destroy = strider_mt_destroy,
	.matchsize = sizeof(struct xt_strider_info),
	.usersize = offsetof(struct xt_strider_info, set),
	.me = THIS_MODULE,
};

static int __init strider_mt_init(void)
{
	return xt_register_match(&xt_strider_mt_reg);
}

static void __exit strider_mt_exit(void)
{
	xt_unregister_match(&xt_strider_mt_reg);
}

module_init(strider_mt_init);
module_exit(strider_mt_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_strider");
MODULE_ALIAS("ip6t_strider");
