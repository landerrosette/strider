#ifndef STRIDER_MATCHING_H
#define STRIDER_MATCHING_H


#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/types.h>

int __init strider_matching_init(void);

void strider_matching_cleanup(void);

int strider_matching_add_pattern(const char *pattern);

int strider_matching_del_pattern(const char *pattern);

bool strider_matching_match_skb(const struct sk_buff *skb);


#endif //STRIDER_MATCHING_H
