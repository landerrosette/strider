/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright (C) 2025-2026 landerrosette
 */

#ifndef STRIDER_XT_STRIDER_H
#define STRIDER_XT_STRIDER_H

#include <linux/types.h>
#include <strider/uapi/limits.h>

enum {
    XT_STRIDER_FLAG_INVERT = 0x01,
};

struct xt_strider_info {
    __u16 from_offset;
    __u16 to_offset;
    char set_name[STRIDER_MAX_SET_NAME_SIZE];
    __u8 flags;

    // used internally by the kernel
    struct strider_set __attribute__((aligned(8))) *set;
};

#endif //STRIDER_XT_STRIDER_H
