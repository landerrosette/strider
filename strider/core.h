#ifndef STRIDER_CORE_H
#define STRIDER_CORE_H


#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/types.h>
#include <strider/strider.h>

struct strider_ac;
struct strider_set;

int __init strider_core_init(void);
void strider_core_exit(void);

int strider_set_create(struct net *net, const char *set_name);
int strider_set_unlink(struct net *net, const char *set_name);
int strider_set_add_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len);
int strider_set_del_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len);


#endif //STRIDER_CORE_H
