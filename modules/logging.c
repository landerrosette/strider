#include <linux/kernel.h>
#include <linux/module.h>
#include "logging.h"
#include "rule.h"

static const char *wdum_rule_pattern_type_names[] = {
    "WDUM_SIMPLE",
    "WDUM_REGEX",
};

static const char *wdum_rule_filter_type_names[] = {
    "WDUM_GENERAL",
    "WDUM_HTTP",
    "WDUM_DNS",
};

void wdum_log_filter(const char *pattern,
                     unsigned int pattern_type,
                     unsigned int filter_type) {
    pr_info("%s: Packet filtered by rule: pattern=\"%s\", pattern_type=%s, filter_type=%s\n",
            module_name(THIS_MODULE),
            pattern,
            wdum_rule_pattern_type_names[pattern_type],
            wdum_rule_filter_type_names[filter_type]);
}

void wdum_log_rule_config(unsigned int op,
                          const char *pattern,
                          unsigned int pattern_type,
                          unsigned int filter_type) {
    char *op_string = "";
    switch (op) {
        case WDUM_RULE_ADD:
            op_string = "added";
            break;
        case WDUM_RULE_DELETE:
            op_string = "deleted";
            break;
        case WDUM_RULE_UPDATE:
            op_string = "updated";
            break;
        default:
            break;
    }
    pr_info("%s: Rule %s: pattern=\"%s\", pattern_type=%s, filter_type=%s\n",
            module_name(THIS_MODULE),
            op_string,
            pattern,
            wdum_rule_pattern_type_names[pattern_type],
            wdum_rule_filter_type_names[filter_type]);
}

void wdum_log_error(const char* attempt) {
    pr_warn("%s: Error %s\n", module_name(THIS_MODULE), attempt);
}
