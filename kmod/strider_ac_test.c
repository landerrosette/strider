#include "strider_ac.h"

#include <kunit/test.h>

struct ac_test_match_ctx {
    struct kunit *test;
    bool found;
};

static int ac_test_match_cb(void *cb_ctx) {
    struct ac_test_match_ctx *ctx = cb_ctx;
    ctx->found = true;
    return 0;
}

// Test case 1: A single, simple match
static void strider_ac_test_simple_match(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct ac_test_match_ctx ctx = {.test = test, .found = false};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "hello world", 11, ac_test_match_cb, &ctx);

    KUNIT_EXPECT_TRUE(test, ctx.found);
}

// Test case 2: Multiple matches with overlapping patterns
static void strider_ac_test_multi_match_overlap(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct ac_test_match_ctx ctx = {.test = test, .found = false};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "ushers", 6, ac_test_match_cb, &ctx);

    KUNIT_EXPECT_TRUE(test, ctx.found);
}

// Test case 3: Failure transitions
static void strider_ac_test_failure_transitions(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct ac_test_match_ctx ctx = {.test = test, .found = false};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "ashe", 4, ac_test_match_cb, &ctx);

    KUNIT_EXPECT_TRUE(test, ctx.found);
}

// Test case 4: No match
static void strider_ac_test_no_match(struct kunit *test) {
    const struct strider_ac_automaton *automaton = test->priv;
    struct strider_ac_match_state state;
    struct ac_test_match_ctx ctx = {.test = test, .found = false};

    strider_ac_match_state_init(&state, automaton);
    strider_ac_automaton_feed(&state, "goodbye planet", 14, ac_test_match_cb, &ctx);

    KUNIT_EXPECT_FALSE(test, ctx.found);
}

static int strider_ac_test_init(struct kunit *test) {
    const char * const patterns[] = {
        "hello",
        "she",
        "he",
        "hers",
    };
    size_t num_patterns = ARRAY_SIZE(patterns);

    struct strider_ac_automaton *automaton = strider_ac_automaton_build(patterns, num_patterns);
    if (IS_ERR(automaton))
        return PTR_ERR(automaton);

    test->priv = automaton;
    return 0;
}

static void strider_ac_test_exit(struct kunit *test) {
    strider_ac_automaton_destroy(test->priv);
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
