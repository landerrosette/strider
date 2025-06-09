#ifndef STRIDER_KERNEL_MATCHING_H
#define STRIDER_KERNEL_MATCHING_H


#include <linux/skbuff.h>
#include <linux/types.h>

enum strider_verdict {
    STRIDER_VERDICT_DROP,
    STRIDER_VERDICT_ACCEPT,
    STRIDER_VERDICT_NOMATCH,
};

int strider_matching_init(void);

void strider_matching_exit(void);

int strider_matching_add_rule(const char *keyword, u8 action);

int strider_matching_del_rule(const char *keyword, u8 action);

enum strider_verdict strider_matching_packet(struct sk_buff *skb);


#endif //STRIDER_KERNEL_MATCHING_H
