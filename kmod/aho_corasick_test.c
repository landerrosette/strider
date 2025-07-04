#include "aho_corasick.h"

#include <kunit/test.h>

struct strider_ac_test_match_ctx {
    struct kunit *test;
    u32 found_mask;
};

static int strider_ac_test_match_cb(const void *priv, size_t offset, void *cb_ctx) {
    struct strider_ac_test_match_ctx *ctx = cb_ctx;
    uintptr_t pattern_id = (uintptr_t) priv; // priv is the pattern's bitmask identifier
    KUNIT_ASSERT_LT(ctx->test, pattern_id, 32);
    ctx->found_mask |= 1U << pattern_id;
    return 0;
}

// Test case 1: A single, simple match
static void strider_ac_test_simple_match(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct strider_ac_test_match_ctx ctx = {.test = test, .found_mask = 0};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "hello world", 11, strider_ac_test_match_cb, &ctx);

    KUNIT_EXPECT_TRUE(test, ctx.found_mask & (1U << 0)); // pattern 0 is "hello"
}

// Test case 2: Multiple matches with overlapping patterns
static void strider_ac_test_multi_match_overlap(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct strider_ac_test_match_ctx ctx = {.test = test, .found_mask = 0};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "ushers", 6, strider_ac_test_match_cb, &ctx);

    KUNIT_EXPECT_TRUE(test, ctx.found_mask & (1U << 1)); // found "she"
    KUNIT_EXPECT_TRUE(test, ctx.found_mask & (1U << 2)); // found "he"
    KUNIT_EXPECT_TRUE(test, ctx.found_mask & (1U << 3)); // found "hers"
}

// Test case 3: Failure transitions
static void strider_ac_test_failure_transitions(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct strider_ac_test_match_ctx ctx = {.test = test, .found_mask = 0};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "ashe", 4, strider_ac_test_match_cb, &ctx);

    KUNIT_EXPECT_TRUE(test, ctx.found_mask & (1U << 1)); // found "she"
    KUNIT_EXPECT_TRUE(test, ctx.found_mask & (1U << 2)); // found "he"
}

// Test case 4: No match
static void strider_ac_test_no_match(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct strider_ac_test_match_ctx ctx = {.test = test, .found_mask = 0};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "goodbye planet", 14, strider_ac_test_match_cb, &ctx);

    KUNIT_EXPECT_EQ(test, ctx.found_mask, 0);
}

static int strider_ac_test_init(struct kunit *test) {
    struct strider_ac_input patterns[] = {
        {.pattern = "hello", .len = 5, .priv = (void *) 0},
        {.pattern = "she", .len = 3, .priv = (void *) 1},
        {.pattern = "he", .len = 2, .priv = (void *) 2},
        {.pattern = "hers", .len = 4, .priv = (void *) 3},
    };
    LIST_HEAD(inputs_head);
    for (size_t i = 0; i < ARRAY_SIZE(patterns); ++i)
        list_add_tail(&patterns[i].list, &inputs_head);

    struct strider_ac_automaton *automaton = strider_ac_automaton_build(&inputs_head);
    if (IS_ERR(automaton))
        return PTR_ERR(automaton);

    test->priv = automaton;
    return 0;
}

static void strider_ac_test_exit(struct kunit *test) {
    strider_ac_automaton_free(test->priv);
}

static struct kunit_case strider_ac_test_cases[] = {
    KUNIT_CASE(strider_ac_test_simple_match),
    KUNIT_CASE(strider_ac_test_multi_match_overlap),
    KUNIT_CASE(strider_ac_test_failure_transitions),
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
