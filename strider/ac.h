#ifndef STRIDER_AC_H
#define STRIDER_AC_H


#include <linux/types.h>

struct strider_ac;

struct strider_ac_target {
    const u8 *pattern;
    size_t pattern_len;

    struct list_head list; // for internal use
};

struct strider_ac_match_state {
    const void *cursor;
};

int strider_ac_caches_create(void);
void strider_ac_caches_destroy(void);

struct strider_ac *strider_ac_create(gfp_t gfp_mask);
void strider_ac_schedule_destroy(struct strider_ac *ac);
int strider_ac_add_target(struct strider_ac *ac, struct strider_ac_target *target, gfp_t gfp_mask);
int strider_ac_compile(struct strider_ac *ac);

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state);
int strider_ac_match(struct strider_ac_match_state *state, const u8 *data, size_t len,
                     int (*cb)(const struct strider_ac_target *target, size_t pos, void *ctx), void *cb_ctx);


#endif //STRIDER_AC_H
