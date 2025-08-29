#ifndef STRIDER_CORE_H
#define STRIDER_CORE_H


#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/types.h>
#include <strider/uapi/limits.h>
#include <strider/strider.h>

struct strider_ac;

struct strider_pattern {
    struct list_head list;
    size_t len;
    u8 data[];
};

struct strider_set {
    struct strider_ac __rcu *ac;
    struct mutex lock;
    struct hlist_node node;
    refcount_t refcount;
    struct list_head patterns;
    char name[STRIDER_MAX_SET_NAME_SIZE];
};

int __init strider_core_init(void);
void strider_core_exit(void);
int strider_set_create(struct net *net, const char *set_name);
int strider_set_destroy(struct net *net, const char *set_name);
int strider_set_add_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len);
int strider_set_del_pattern(struct net *net, const char *set_name, const u8 *pattern, size_t len);


#endif //STRIDER_CORE_H
