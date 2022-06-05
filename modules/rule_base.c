#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>
#include "rule_base.h"
#include "rule.h"
#include "logging.h"

static struct list_head wdum_rule_list_heads[WDUM_NUM_RULE_FILTER_TYPES];

/* exported for wdum_filter */
const struct wdum_rule* wdum_read_next_rule(unsigned int filter_type,
                                            const struct wdum_rule* curr_rule) {
    const struct wdum_rule* next_rule;
    struct list_head* head = &wdum_rule_list_heads[filter_type];

    if (curr_rule == NULL) {
        next_rule = list_first_entry(head, struct wdum_rule, list);
    } else {
        next_rule = list_next_entry(curr_rule, list);
    }

    if (list_entry_is_head(next_rule, head, list))
        return NULL;
    return next_rule;
}
EXPORT_SYMBOL(wdum_read_next_rule);

void wdum_add_rule(const char *pattern,
                   unsigned int pattern_type,
                   unsigned int filter_type) {
    struct wdum_rule *new_rule;
    char *ptn;

    /* Create a wdum_rule node and add it to the tail of the list. */
    new_rule = (struct wdum_rule *)kmalloc(sizeof(struct wdum_rule), GFP_KERNEL);
    if (new_rule == NULL)
        goto err_new_rule;
    ptn = (char *)kmalloc(sizeof(char) * (strlen(pattern) + 1), GFP_KERNEL);
    if (ptn == NULL)
        goto err_ptn;
    strcpy(ptn, pattern);
    new_rule->pattern = ptn;
    new_rule->pattern_type = pattern_type;
    list_add_tail(&new_rule->list, &wdum_rule_list_heads[filter_type]);
    wdum_log_rule_config(WDUM_RULE_ADD, pattern, pattern_type, filter_type);

    return;

err_ptn:
    kfree(new_rule);
err_new_rule:
    wdum_log_error("adding rule");
}

void wdum_delete_rule(const char *pattern,
                      unsigned int pattern_type,
                      unsigned int filter_type) {
    struct wdum_rule *pos, *n;

    list_for_each_entry_safe(pos, n, &wdum_rule_list_heads[filter_type], list) {
        if (pos->pattern_type == pattern_type && strcmp(pos->pattern, pattern) == 0) {
            list_del(&pos->list);
            kfree(pos->pattern);
            kfree(pos);
            wdum_log_rule_config(WDUM_RULE_DELETE, pattern, pattern_type, filter_type);
        }
    }
}

void wdum_update_rule(const char *old_pattern, const char *new_pattern) {
    struct wdum_rule *pos;
    char *nptn;
    int i;

    /* Search for rules with matching pattern and substitute their pattern. */
    for (i = 0; i < WDUM_NUM_RULE_FILTER_TYPES; i++) {
        list_for_each_entry(pos, &wdum_rule_list_heads[i], list) {
            if (strcmp(pos->pattern, old_pattern) == 0) {
                nptn = (char *)kmalloc(sizeof(char) * (strlen(new_pattern) + 1), GFP_KERNEL);
                if (nptn == NULL)
                    goto err_nptn;
                strcpy(nptn, new_pattern);
                kfree(pos->pattern);
                pos->pattern = nptn;
                wdum_log_rule_config(WDUM_RULE_UPDATE, pos->pattern, pos->pattern_type, i);
            }
        }
    }

    return;

err_nptn:
    wdum_log_error("updating rule");
}

void wdum_rule_base_init(void) {
    int i;

    for (i = 0; i < WDUM_NUM_RULE_FILTER_TYPES; i++) {
        INIT_LIST_HEAD(&wdum_rule_list_heads[i]);
    }
}

void wdum_rule_base_dest(void) {
    struct wdum_rule *pos, *n;
    int i;

    for (i = 0; i < WDUM_NUM_RULE_FILTER_TYPES; i++) {
        list_for_each_entry_safe(pos, n, &wdum_rule_list_heads[i], list) {
            list_del(&pos->list);
            kfree(pos->pattern);
            kfree(pos);
        }
    }
}
