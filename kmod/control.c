#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "control.h"

#include <linux/compiler_attributes.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <net/genetlink.h>
#include <strider/protocol.h>

#include "matching.h"

static const struct nla_policy strider_nl_rule_policy[STRIDER_NLA_MAX + 1] = {
    [STRIDER_NLA_PATTERN] = {.type = NLA_NUL_STRING, .len = STRIDER_PATTERN_MAX_LEN},
    [STRIDER_NLA_ACTION] = {.type = NLA_U8},
};

static int strider_nl_parse_rule_attrs(struct genl_info *info, const char **pattern,
                                       enum strider_action *action) {
    if (!info->attrs[STRIDER_NLA_PATTERN] || !info->attrs[STRIDER_NLA_ACTION])
        return -EINVAL;

    *pattern = nla_data(info->attrs[STRIDER_NLA_PATTERN]);
    u8 raw_action = nla_get_u8(info->attrs[STRIDER_NLA_ACTION]);
    switch (raw_action) {
        case STRIDER_ACTION_DROP:
        case STRIDER_ACTION_ACCEPT:
            *action = raw_action;
            break;
        default:
            return -EINVAL;
    }

    return 0;
}

static int __cold strider_nl_add_rule_doit(struct sk_buff *skb, struct genl_info *info) {
    const char *pattern;
    enum strider_action action;

    int ret = strider_nl_parse_rule_attrs(info, &pattern, &action);
    if (ret < 0) goto out;

    ret = strider_matching_add_rule(pattern, action);
    if (ret < 0) goto out;

out:
    return ret;
}

static int __cold strider_nl_del_rule_doit(struct sk_buff *skb, struct genl_info *info) {
    const char *pattern;
    enum strider_action action;

    int ret = strider_nl_parse_rule_attrs(info, &pattern, &action);
    if (ret < 0) goto out;

    ret = strider_matching_del_rule(pattern, action);
    if (ret < 0) goto out;

out:
    return ret;
}

static const struct genl_ops strider_genl_ops[] = {
    {
        .cmd = STRIDER_CMD_ADD_RULE,
        .flags = GENL_ADMIN_PERM,
        .policy = strider_nl_rule_policy,
        .doit = strider_nl_add_rule_doit,
    },
    {
        .cmd = STRIDER_CMD_DEL_RULE,
        .flags = GENL_ADMIN_PERM,
        .policy = strider_nl_rule_policy,
        .doit = strider_nl_del_rule_doit,
    },
};

static struct genl_family strider_genl_family = {
    .name = STRIDER_GENL_FAMILY_NAME,
    .version = STRIDER_GENL_VERSION,
    .maxattr = STRIDER_NLA_MAX,
    .ops = strider_genl_ops,
    .n_ops = ARRAY_SIZE(strider_genl_ops),
    .module = THIS_MODULE,
};

int __init strider_control_init(void) {
    int ret = genl_register_family(&strider_genl_family);
    if (ret < 0)
        pr_err("Failed to register generic netlink family: %d\n", ret);
    return ret;
}

void strider_control_cleanup(void) {
    genl_unregister_family(&strider_genl_family);
}
