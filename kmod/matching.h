#ifndef STRIDER_KMOD_MATCHING_H
#define STRIDER_KMOD_MATCHING_H


#include <linux/init.h>
#include <linux/skbuff.h>
#include <strider/defs.h>

enum strider_verdict {
    STRIDER_VERDICT_NOMATCH,
    STRIDER_VERDICT_DROP,
    STRIDER_VERDICT_ACCEPT,
};

int __init strider_matching_init(void);

void strider_matching_cleanup(void);

int strider_matching_add_rule(const char *pattern, enum strider_action action);

int strider_matching_del_rule(const char *pattern, enum strider_action action);

enum strider_verdict strider_matching_get_verdict(struct sk_buff *skb);


#endif //STRIDER_KMOD_MATCHING_H
