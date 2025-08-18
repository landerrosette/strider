#ifndef STRIDER_AC_H
#define STRIDER_AC_H


#include <linux/types.h>

struct strider_ac;

struct ac_match_state {
    const void *cursor;
};

struct strider_ac *ac_init(gfp_t gfp_mask);

void ac_schedule_destroy(struct strider_ac *ac);

int ac_add_pattern(struct strider_ac *ac, const u8 *pattern, size_t len, gfp_t gfp_mask);

int ac_compile(struct strider_ac *ac, gfp_t gfp_mask);

void ac_match_init(const struct strider_ac *ac, struct ac_match_state *state);

bool ac_match_next(struct ac_match_state *state, const u8 *data, size_t len);


#endif //STRIDER_AC_H
