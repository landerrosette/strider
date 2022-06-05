#include <linux/textsearch.h>
#include <linux/limits.h>
#include <linux/skbuff.h>
#include "matchers.h"
#include "rule.h"
#include "logging.h"

static bool wdum_simple_match(const struct wdum_rule *rule,
                              struct sk_buff *skb,
                              unsigned int from,
                              unsigned int to) {
    int pos;
    struct ts_config *conf;

    conf = textsearch_prepare("bm", rule->pattern, strlen(rule->pattern), GFP_KERNEL, TS_AUTOLOAD);
    if (IS_ERR(conf)) {
        wdum_log_error("initializing matcher");
        return false;
    }
    pos = skb_find_text(skb, from, to, conf);
    textsearch_destroy(conf);

    if (pos != UINT_MAX)
        return true;
    return false;
}

static bool wdum_regex_match(const struct wdum_rule *rule,
                             struct sk_buff *skb,
                             unsigned int from,
                             unsigned int to) {
    int pos;
    struct ts_config *conf;

    conf = textsearch_prepare("regex", rule->pattern, strlen(rule->pattern), GFP_KERNEL, TS_AUTOLOAD);
    if (IS_ERR(conf)) {
        wdum_log_error("initializing matcher");
        return false;
    }
    pos = skb_find_text(skb, from, to, conf);
    textsearch_destroy(conf);

    if (pos != UINT_MAX)
        return true;
    return false;
}

bool (*wdum_matchers[WDUM_NUM_RULE_PATTERN_TYPES])(const struct wdum_rule *rule,
                                                   struct sk_buff *skb,
                                                   unsigned int from,
                                                   unsigned int to) = {
    wdum_simple_match,
    wdum_regex_match,
};
