#ifndef STRIDER_KERNEL_MATCHING_H
#define STRIDER_KERNEL_MATCHING_H


#include <linux/skbuff.h>
#include <linux/types.h>

int strider_matching_init(void);

void strider_matching_exit(void);

int strider_matching_add_rule(const char *keyword, u8 action);

int strider_matching_del_rule(const char *keyword, u8 action);

u8 strider_matching_packet(struct sk_buff *skb);


#endif //STRIDER_KERNEL_MATCHING_H
