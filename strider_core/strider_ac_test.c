#include "strider_ac.h"

#include <kunit/test.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

// Test case 1: A single, simple match
static void strider_ac_test_simple_match(struct kunit *test) {
    const struct strider_ac *ac = test->priv;
    struct strider_ac_match_state state;

    strider_ac_match_init(ac, &state);
    bool found = strider_ac_match_next(&state, "hello world", 11);
    KUNIT_EXPECT_TRUE(test, found);
}

// Test case 2: Multiple matches with overlapping patterns
static void strider_ac_test_multi_match_overlap(struct kunit *test) {
    const struct strider_ac *ac = test->priv;
    struct strider_ac_match_state state;

    strider_ac_match_init(ac, &state);
    bool found = strider_ac_match_next(&state, "ushers", 6);
    KUNIT_EXPECT_TRUE(test, found);
}

// Test case 3: No match
static void strider_ac_test_no_match(struct kunit *test) {
    const struct strider_ac *ac = test->priv;
    struct strider_ac_match_state state;

    strider_ac_match_init(ac, &state);
    bool found = strider_ac_match_next(&state, "goodbye planet", 14);
    KUNIT_EXPECT_FALSE(test, found);
}

static int strider_ac_test_init(struct kunit *test) {
    const char *patterns[] = {
        "hello",
        "she",
        "he",
        "hers",
    };

    int ret = 0;
    struct strider_ac *ac = strider_ac_init(GFP_KERNEL);
    if (IS_ERR(ac)) {
        ret = PTR_ERR(ac);
        goto out;
    }
    for (int i = 0; i < ARRAY_SIZE(patterns); ++i) {
        ret = strider_ac_add_pattern(ac, (const u8 *) patterns[i], strlen(patterns[i]), GFP_KERNEL);
        if (ret < 0)
            goto fail;
    }
    ret = strider_ac_compile(ac, GFP_KERNEL);
    if (ret < 0)
        goto fail;

    test->priv = ac;

out:
    return ret;

fail:
    strider_ac_destroy(ac);
    goto out;
}

static void strider_ac_test_exit(struct kunit *test) {
    strider_ac_destroy(test->priv);
}

static struct kunit_case strider_ac_test_cases[] = {
    KUNIT_CASE(strider_ac_test_simple_match),
    KUNIT_CASE(strider_ac_test_multi_match_overlap),
    KUNIT_CASE(strider_ac_test_no_match),
    {}
};

static struct kunit_suite strider_ac_test_suite = {
    .name = "strider_ac_test",
    .init = strider_ac_test_init,
    .exit = strider_ac_test_exit,
    .test_cases = strider_ac_test_cases,
};

kunit_test_suite(strider_ac_test_suite);

MODULE_LICENSE("Dual MIT/GPL");
