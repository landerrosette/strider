#ifndef _RULE_BASE_H
#define _RULE_BASE_H

void wdum_add_rule(const char *pattern,
                   unsigned int pattern_type,
                   unsigned int filter_type);

void wdum_delete_rule(const char *pattern,
                      unsigned int pattern_type,
                      unsigned int filter_type);

void wdum_update_rule(const char *old_pattern, const char *new_pattern);

void wdum_rule_base_init(void);

void wdum_rule_base_dest(void);

#endif /*_RULE_BASE_H*/
