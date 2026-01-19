// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2025-2026 landerrosette <57791410+landerrosette@users.noreply.github.com>
 */

#include <stdint.h>
#include <stdio.h>
#include <xtables.h>

#include "xt_strider.h"

enum {
    O_FROM,
    O_TO,
    O_MATCH_SET,
    O_INVERT,
};

static void strider_help(void) {
    printf(
        "strider match options:\n"
        "  --from OFFSET               Set the offset to start searching from\n"
        "  --to OFFSET                 Set the offset to stop searching\n"
        "  [!] --match-set SET_NAME    Match against the named pattern set\n");
}

static const struct xt_option_entry strider_opts[] = {
    {
        .name = "from", .type = XTTYPE_UINT16, .id = O_FROM, .flags = XTOPT_PUT,
        XTOPT_POINTER(struct xt_strider_info, from_offset)
    },
    {
        .name = "to", .type = XTTYPE_UINT16, .id = O_TO, .flags = XTOPT_PUT,
        XTOPT_POINTER(struct xt_strider_info, to_offset)
    },
    {
        .name = "match-set", .type = XTTYPE_STRING, .id = O_MATCH_SET, .flags = XTOPT_INVERT | XTOPT_MAND | XTOPT_PUT,
        XTOPT_POINTER(struct xt_strider_info, set_name)
    },
    XTOPT_TABLEEND
};

static void strider_init(struct xt_entry_match *match) {
    struct xt_strider_info *info = (struct xt_strider_info *) match->data;
    info->to_offset = UINT16_MAX;
}

static void strider_parse(struct xt_option_call *cb) {
    xtables_option_parse(cb);
    if (cb->invert)
        ((struct xt_strider_info *) cb->data)->flags |= XT_STRIDER_FLAG_INVERT;
}

static void strider_save(const void *ip, const struct xt_entry_match *match) {
    const struct xt_strider_info *info = (const struct xt_strider_info *) match->data;
    if (info->flags & XT_STRIDER_FLAG_INVERT)
        printf(" !");
    printf(" --match-set %s", info->set_name);
    if (info->from_offset != 0)
        printf(" --from %u", info->from_offset);
    if (info->to_offset != UINT16_MAX)
        printf(" --to %u", info->to_offset);
}

static void strider_print(const void *ip, const struct xt_entry_match *match, int numeric) {
    printf(" -m strider");
    strider_save(ip, match);
}

static struct xtables_match strider_mt_reg = {
    .name = "strider",
    .family = NFPROTO_UNSPEC,
    .version = XTABLES_VERSION,
    .size = XT_ALIGN(sizeof(struct xt_strider_info)),
    .userspacesize = offsetof(struct xt_strider_info, set),
    .help = strider_help,
    .init = strider_init,
    .print = strider_print,
    .save = strider_save,
    .x6_parse = strider_parse,
    .x6_options = strider_opts,
};

static __attribute__((constructor)) void strider_mt_ldr(void) {
    xtables_register_match(&strider_mt_reg);
}
