#ifndef _MATCHERS_H
#define _MATCHERS_H

#include <linux/skbuff.h>
#include "rule.h"

extern bool (*wdum_matchers[WDUM_NUM_RULE_PATTERN_TYPES])(const struct wdum_rule *rule,
                                                          struct sk_buff *skb,
                                                          unsigned int from,
                                                          unsigned int to);

#endif /*_MATCHERS_H*/
