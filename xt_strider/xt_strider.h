#ifndef XT_STRIDER_H
#define XT_STRIDER_H


#include <strider/uapi/limits.h>
#include <linux/types.h>

struct xt_strider_info {
    __u16 from;
    __u16 to;
    char set_name[STRIDER_MAX_SET_NAME_SIZE];
    __u8 invert;

    // used internally by the kernel
    struct strider_set __attribute__((aligned(8))) *set;
};


#endif //XT_STRIDER_H
