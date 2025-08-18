#include "ac.h"

#include <kunit/test.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/types.h>

static struct strider_ac *ac_build_from_patterns(const char *patterns[]) {
    struct strider_ac *ac = ac_init(GFP_KERNEL);
    if (IS_ERR(ac))
        goto out;
    int ret;
    for (int i = 0; patterns[i]; ++i) {
        ret = ac_add_pattern(ac, (const u8 *) patterns[i], strlen(patterns[i]), GFP_KERNEL);
        if (ret < 0)
            goto fail;
    }
    ret = ac_compile(ac, GFP_KERNEL);
    if (ret < 0)
        goto fail;
out:
    return ac;
fail:
    ac_schedule_destroy(ac);
    return ERR_PTR(ret);
}

// Test case 1: Basic match
static void ac_test_basic_match(struct kunit *test) {
    const char *patterns[] = {
        "he",
        "she",
        NULL
    };
    struct strider_ac *ac = ac_build_from_patterns(patterns);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct ac_match_state state;
    ac_match_init(ac, &state);
    bool found = ac_match_next(&state, "ushers", 6);
    KUNIT_EXPECT_TRUE(test, found);

    ac_schedule_destroy(ac);
}

// Test case 2: Failure path transition
static void ac_test_failure_path_transition(struct kunit *test) {
    const char *patterns[] = {
        "abcd",
        "bcf",
        NULL
    };
    struct strider_ac *ac = ac_build_from_patterns(patterns);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct ac_match_state state;
    ac_match_init(ac, &state);
    bool found = ac_match_next(&state, "abcf", 4);
    KUNIT_EXPECT_TRUE(test, found);

    ac_schedule_destroy(ac);
}

// Test case 3: Streaming match across blocks
static void ac_test_streaming_match(struct kunit *test) {
    const char *patterns[] = {
        "pattern",
        NULL
    };
    struct strider_ac *ac = ac_build_from_patterns(patterns);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct ac_match_state state;
    ac_match_init(ac, &state);
    bool found = ac_match_next(&state, "pat", 3);
    KUNIT_EXPECT_FALSE(test, found);
    found = ac_match_next(&state, "tern", 4);
    KUNIT_EXPECT_TRUE(test, found);

    ac_schedule_destroy(ac);
}

// Test case 4: Empty input
static void ac_test_empty_input(struct kunit *test) {
    const char *patterns[] = {
        "abc",
        NULL
    };
    struct strider_ac *ac = ac_build_from_patterns(patterns);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);

    struct ac_match_state state;
    ac_match_init(ac, &state);
    bool found = ac_match_next(&state, "", 0);
    KUNIT_EXPECT_FALSE(test, found);

    ac_schedule_destroy(ac);
}

static struct kunit_case ac_test_cases[] = {
    KUNIT_CASE(ac_test_basic_match),
    KUNIT_CASE(ac_test_failure_path_transition),
    KUNIT_CASE(ac_test_streaming_match),
    KUNIT_CASE(ac_test_empty_input),
    {}
};

static struct kunit_suite ac_test_suite = {
    .name = "strider_ac_test",
    .test_cases = ac_test_cases,
};

kunit_test_suite(ac_test_suite);

MODULE_LICENSE("Dual MIT/GPL");
