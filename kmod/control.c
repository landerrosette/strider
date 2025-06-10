#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "control.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <strider/protocol.h>

#include "matching.h"

static int strider_nl_add_rule_doit(struct sk_buff *skb, struct genl_info *info);

static const struct nla_policy strider_add_rule_policy[STRIDER_NLA_MAX + 1] = {
    [STRIDER_NLA_PATTERN] = {.type = NLA_NUL_STRING, .len = STRIDER_PATTERN_MAX_LEN},
    [STRIDER_NLA_ACTION] = {.type = NLA_U8},
};

static struct genl_ops strider_genl_ops[] = {
    {
        .cmd = STRIDER_CMD_ADD_RULE,
        .flags = GENL_ADMIN_PERM,
        .policy = strider_add_rule_policy,
        .doit = strider_nl_add_rule_doit,
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

static int strider_nl_add_rule_doit(struct sk_buff *skb, struct genl_info *info) {
    if (!info->attrs[STRIDER_NLA_PATTERN] || !info->attrs[STRIDER_NLA_ACTION])
        return -EINVAL;

    char *pattern = nla_data(info->attrs[STRIDER_NLA_PATTERN]);
    u8 action = nla_get_u8(info->attrs[STRIDER_NLA_ACTION]);
    if (action == STRIDER_ACTION_UNSPEC)
        return -EINVAL;

    return strider_matching_add_rule(pattern, action);
}

int strider_control_init(void) {
    int ret = genl_register_family(&strider_genl_family);
    if (ret < 0)
        pr_err("Failed to register genl family: %d\n", ret);
    return ret;
}

void strider_control_exit(void) {
    genl_unregister_family(&strider_genl_family);
}
