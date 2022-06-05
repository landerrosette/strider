#ifndef _RULE_H
#define _RULE_H

struct wdum_rule {
    const char *pattern;
    unsigned int pattern_type;
    struct list_head list;
};

enum wdum_rule_pattern_types {
    WDUM_SIMPLE,
    WDUM_REGEX,
    WDUM_NUM_RULE_PATTERN_TYPES,
};

enum wdum_rule_filter_types {
    WDUM_GENERAL,
    WDUM_HTTP,
    WDUM_DNS,
    WDUM_NUM_RULE_FILTER_TYPES,
};

enum wdum_rule_ops {
    WDUM_RULE_ADD,
    WDUM_RULE_DELETE,
    WDUM_RULE_UPDATE,
    WDUM_NUM_RULE_OPS,
};

#endif /*_RULE_H*/
