#ifndef STRIDER_AC_H
#define STRIDER_AC_H


#include <linux/types.h>

struct strider_ac;

struct strider_ac_target {
    const u8 *pattern;
    size_t pattern_len;
};

struct strider_ac_match_state {
    u32 state_id;
};

struct strider_ac *strider_ac_build(const struct strider_ac_target *(*get_target)(void *ctx), void *iter_ctx);
void strider_ac_schedule_destroy(struct strider_ac *ac);

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state);
int strider_ac_match(struct strider_ac_match_state *state, const u8 *data, size_t len,
                     int (*cb)(const struct strider_ac_target *target, size_t pos, void *ctx), void *cb_ctx);


#endif //STRIDER_AC_H
