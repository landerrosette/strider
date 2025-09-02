#include "ac.h"

#include <kunit/test.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

struct strider_ac_test_target {
    struct strider_ac_target ac_target;
    int id;
};

struct strider_ac_test_match_info {
    struct kunit *test;
    bool exit_early;
    int count;
    u32 ids;
    u32 positions;
};

static struct strider_ac *strider_ac_build_from_targets(struct strider_ac_test_target targets[]) {
    struct strider_ac *ac = strider_ac_init(GFP_KERNEL);
    if (IS_ERR(ac))
        return ac;
    int ret = 0;
    for (int i = 0; targets[i].ac_target.pattern; ++i) {
        ret = strider_ac_add_target(ac, &targets[i].ac_target, GFP_KERNEL);
        if (ret < 0)
            goto fail;
    }
    ret = strider_ac_compile(ac, GFP_KERNEL);
    if (ret < 0)
        goto fail;
    return ac;
fail:
    strider_ac_schedule_destroy(ac);
    return ERR_PTR(ret);
}

int strider_ac_test_match_cb(const struct strider_ac_target *target, size_t pos, void *ctx) {
    struct strider_ac_test_match_info *info = ctx;
    ++info->count;
    int found_id = container_of(target, struct strider_ac_test_target, ac_target)->id;
    KUNIT_ASSERT_LT(info->test, found_id, 32);
    info->ids |= 1U << found_id;
    KUNIT_ASSERT_LT(info->test, pos, 32);
    info->positions |= 1U << pos;
    return info->exit_early ? 1 : 0;
}

static void strider_ac_test_single_pattern_single_match(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "hello", .pattern_len = 5}, .id = 0},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "say hello world", 15, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 1);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 8);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_single_pattern_multiple_matches(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "test", .pattern_len = 4}, .id = 0},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "this is a test, another test", 28, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 2);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 13);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 27);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_no_match(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "abc", .pattern_len = 3}, .id = 0},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "xyz_def_ghi", 11, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 0);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_multiple_patterns_at_same_position(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "he", .pattern_len = 2}, .id = 0},
        {.ac_target = (struct strider_ac_target){.pattern = "she", .pattern_len = 3}, .id = 1},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "she said", 8, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 2);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 1);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 2);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_overlapping_patterns(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "abab", .pattern_len = 4}, .id = 0},
        {.ac_target = (struct strider_ac_target){.pattern = "baba", .pattern_len = 4}, .id = 1},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "ababa", 5, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 2);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 1);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 3);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 4);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_multiple_disjoint_matches(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "error", .pattern_len = 5}, .id = 0},
        {.ac_target = (struct strider_ac_target){.pattern = "warn", .pattern_len = 4}, .id = 1},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "an error occurred, then a warn", 30, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 2);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 1);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 7);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 29);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_early_exit(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "stop", .pattern_len = 4}, .id = 0},
        {.ac_target = (struct strider_ac_target){.pattern = "continue", .pattern_len = 8}, .id = 1},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test, .exit_early = true};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "first stop then continue", 24, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 1);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 9);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_streaming_match(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "abcdef", .pattern_len = 6}, .id = 0},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "abc", 3, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 0);
    strider_ac_match(&state, "def", 3, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 1);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 2);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_empty_input(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "any", .pattern_len = 3}, .id = 0},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "", 0, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 0);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_match_at_start(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "start", .pattern_len = 5}, .id = 0},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "start of text", 13, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 1);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 4);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_match_at_end(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "end", .pattern_len = 3}, .id = 0},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "text ends now end", 17, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 2);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 7);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 16);

    strider_ac_schedule_destroy(ac);
}

static void strider_ac_test_pattern_is_substring_of_another(struct kunit *test) {
    struct strider_ac_test_target targets[] = {
        {.ac_target = (struct strider_ac_target){.pattern = "word", .pattern_len = 4}, .id = 0},
        {.ac_target = (struct strider_ac_target){.pattern = "sword", .pattern_len = 5}, .id = 1},
        {}
    };
    struct strider_ac *ac = strider_ac_build_from_targets(targets);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, "a single sword", 14, strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.count, 2);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 0);
    KUNIT_EXPECT_TRUE(test, info.ids & 1U << 1);
    KUNIT_EXPECT_TRUE(test, info.positions & 1U << 13);

    strider_ac_schedule_destroy(ac);
}

static struct kunit_case strider_ac_test_cases[] = {
    KUNIT_CASE(strider_ac_test_single_pattern_single_match),
    KUNIT_CASE(strider_ac_test_single_pattern_multiple_matches),
    KUNIT_CASE(strider_ac_test_no_match),
    KUNIT_CASE(strider_ac_test_multiple_patterns_at_same_position),
    KUNIT_CASE(strider_ac_test_overlapping_patterns),
    KUNIT_CASE(strider_ac_test_multiple_disjoint_matches),
    KUNIT_CASE(strider_ac_test_early_exit),
    KUNIT_CASE(strider_ac_test_streaming_match),
    KUNIT_CASE(strider_ac_test_empty_input),
    KUNIT_CASE(strider_ac_test_match_at_start),
    KUNIT_CASE(strider_ac_test_match_at_end),
    KUNIT_CASE(strider_ac_test_pattern_is_substring_of_another),
    {}
};

static void strider_ac_test_suite_exit(struct kunit_suite *suite) {
    rcu_barrier();
}

static struct kunit_suite strider_ac_test_suite = {
    .name = "strider_ac_test",
    .suite_exit = strider_ac_test_suite_exit,
    .test_cases = strider_ac_test_cases,
};

kunit_test_suite(strider_ac_test_suite);

MODULE_LICENSE("GPL");
