#ifndef _LOGGING_H
#define _LOGGING_H

void wdum_log_filter(const char *pattern,
                     unsigned int pattern_type,
                     unsigned int filter_type);

void wdum_log_rule_config(unsigned int op,
                          const char *pattern,
                          unsigned int pattern_type,
                          unsigned int filter_type);

void wdum_log_error(const char* attempt);

#endif /*_LOGGING_H*/
