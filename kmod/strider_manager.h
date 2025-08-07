#ifndef STRIDER_MANAGER_H
#define STRIDER_MANAGER_H


#include <linux/init.h>
#include <linux/compiler.h>

struct strider_set;

struct strider_ac_automaton;

int __init strider_manager_init(void);

void __cold strider_manager_cleanup(void);

int __cold strider_set_create(const char *name);

int __cold strider_set_destroy(const char *name);

int __cold strider_set_add_pattern(const char *set_name, const char *pattern);

int __cold strider_set_del_pattern(const char *set_name, const char *pattern);

const struct strider_set *strider_set_lookup_rcu(const char *name);

const struct strider_ac_automaton *strider_set_get_automaton(const struct strider_set *set);


#endif //STRIDER_MANAGER_H
