// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2025-2026 landerrosette <57791410+landerrosette@users.noreply.github.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "netlink.h"

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <net/genetlink.h>
#include <strider/uapi/limits.h>
#include <strider/uapi/netlink.h>

#include "core.h"

static const struct nla_policy strider_set_policy[STRIDER_ATTR_MAX + 1] = {
    [0] = {.strict_start_type = 1},
    [STRIDER_ATTR_SET_NAME] = {.type = NLA_NUL_STRING, .len = STRIDER_MAX_SET_NAME_SIZE - 1},
};

static const struct nla_policy strider_pattern_policy[STRIDER_ATTR_MAX + 1] = {
    [0] = {.strict_start_type = 1},
    [STRIDER_ATTR_SET_NAME] = {.type = NLA_NUL_STRING, .len = STRIDER_MAX_SET_NAME_SIZE - 1},
    [STRIDER_ATTR_PATTERN] = NLA_POLICY_RANGE(NLA_BINARY, 1, STRIDER_MAX_PATTERN_SIZE),
};

static int strider_nl_create_set_doit(struct sk_buff *skb, struct genl_info *info) {
    if (!info->attrs[STRIDER_ATTR_SET_NAME])
        return -EINVAL;
    const char *name = nla_data(info->attrs[STRIDER_ATTR_SET_NAME]);
    if (*name == '\0')
        return -EINVAL;
    return strider_set_create(genl_info_net(info), name);
}

static int strider_nl_destroy_set_doit(struct sk_buff *skb, struct genl_info *info) {
    if (!info->attrs[STRIDER_ATTR_SET_NAME])
        return -EINVAL;
    const char *name = nla_data(info->attrs[STRIDER_ATTR_SET_NAME]);
    if (*name == '\0')
        return -EINVAL;
    return strider_set_remove(genl_info_net(info), name);
}

static int strider_nl_add_pattern_doit(struct sk_buff *skb, struct genl_info *info) {
    if (!info->attrs[STRIDER_ATTR_SET_NAME] || !info->attrs[STRIDER_ATTR_PATTERN])
        return -EINVAL;
    const char *set_name = nla_data(info->attrs[STRIDER_ATTR_SET_NAME]);
    if (*set_name == '\0')
        return -EINVAL;
    return strider_set_add_pattern(genl_info_net(info), set_name, nla_data(info->attrs[STRIDER_ATTR_PATTERN]),
                                   nla_len(info->attrs[STRIDER_ATTR_PATTERN]));
}

static int strider_nl_del_pattern_doit(struct sk_buff *skb, struct genl_info *info) {
    if (!info->attrs[STRIDER_ATTR_SET_NAME] || !info->attrs[STRIDER_ATTR_PATTERN])
        return -EINVAL;
    const char *set_name = nla_data(info->attrs[STRIDER_ATTR_SET_NAME]);
    if (*set_name == '\0')
        return -EINVAL;
    return strider_set_del_pattern(genl_info_net(info), set_name, nla_data(info->attrs[STRIDER_ATTR_PATTERN]),
                                   nla_len(info->attrs[STRIDER_ATTR_PATTERN]));
}

static const struct genl_ops strider_nl_ops[] = {
    {
        .cmd = STRIDER_CMD_CREATE_SET,
        .doit = strider_nl_create_set_doit,
        .policy = strider_set_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = STRIDER_CMD_DESTROY_SET,
        .doit = strider_nl_destroy_set_doit,
        .policy = strider_set_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = STRIDER_CMD_ADD_PATTERN,
        .doit = strider_nl_add_pattern_doit,
        .policy = strider_pattern_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = STRIDER_CMD_DEL_PATTERN,
        .doit = strider_nl_del_pattern_doit,
        .policy = strider_pattern_policy,
        .flags = GENL_ADMIN_PERM,
    },
};

static struct genl_family strider_nl_family __ro_after_init = {
    .name = STRIDER_GENL_FAMILY_NAME,
    .version = STRIDER_GENL_VERSION,
    .maxattr = STRIDER_ATTR_MAX,
    .netnsok = true,
    .parallel_ops = true,
    .n_ops = ARRAY_SIZE(strider_nl_ops),
    .ops = strider_nl_ops,
    .module = THIS_MODULE,
};

int __init strider_netlink_init(void) {
    int ret = genl_register_family(&strider_nl_family);
    if (ret < 0)
        pr_err("failed to register generic netlink family: %d\n", ret);
    return ret;
}

void strider_netlink_exit(void) {
    genl_unregister_family(&strider_nl_family);
}

MODULE_ALIAS_GENL_FAMILY(STRIDER_GENL_FAMILY_NAME);
