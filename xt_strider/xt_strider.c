#include "xt_strider.h"
#include <linux/netfilter/x_tables.h>
#include <strider/strider.h>
#include <linux/skbuff.h>
#include <strider/uapi/limits.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/kernel.h>

static bool strider_mt(const struct sk_buff *skb, struct xt_action_param *par) {
    const struct xt_strider_info *info = par->matchinfo;
    return strider_set_match(info->set, (struct sk_buff *) skb, info->from, info->to) ^ info->invert;
}

static int strider_mt_check(const struct xt_mtchk_param *par) {
    struct xt_strider_info *info = par->matchinfo;
    if (info->set_name[STRIDER_MAX_SET_NAME_SIZE - 1] != '\0')
        return -EINVAL;
    if (info->from > info->to)
        return -EINVAL;
    struct strider_set *set = strider_set_get(par->net, info->set_name);
    if (IS_ERR(set))
        return PTR_ERR(set);
    info->set = set;
    return 0;
}

static void strider_mt_destroy(const struct xt_mtdtor_param *par) {
    strider_set_put(((struct xt_strider_info *) par->matchinfo)->set);
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
