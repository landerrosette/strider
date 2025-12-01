#ifndef STRIDER_CORE_H
#define STRIDER_CORE_H


#include <linux/init.h>
#include <linux/types.h>

int __init strider_core_init(void);
void strider_core_exit(void);

struct net;

int strider_set_create(struct net *net, const char *set_name);
int strider_set_destroy(struct net *net, const char *set_name);
int strider_set_add_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len);
int strider_set_del_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len);


#endif //STRIDER_CORE_H
