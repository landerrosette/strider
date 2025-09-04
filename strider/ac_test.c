#include "ac.h"
#include <kunit/test.h>
#include <kunit/resource.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/bitops.h>

#define STRIDER_AC_TEST_MAX_TARGETS BITS_PER_TYPE(unsigned int)

struct strider_ac_test_target {
    struct strider_ac_target ac_target;
    int id;
};

struct strider_ac_test_match_info {
    struct kunit *test;
    int match_count;
    unsigned int found_id_mask;
};

static int strider_ac_test_resource_init(struct kunit_resource *res, void *ctx) {
    struct strider_ac *ac = strider_ac_init(GFP_KERNEL);
    if (IS_ERR(ac))
        return PTR_ERR(ac);
    res->data = ac;
    return 0;
}

static void strider_ac_test_resource_free(struct kunit_resource *res) {
    strider_ac_schedule_destroy(res->data);
}

static int strider_ac_test_match_cb(const struct strider_ac_target *target, size_t pos, void *ctx) {
    struct strider_ac_test_match_info *info = ctx;
    ++info->match_count;
    int found_id = container_of(target, struct strider_ac_test_target, ac_target)->id;
    KUNIT_ASSERT_LT(info->test, found_id, STRIDER_AC_TEST_MAX_TARGETS);
    info->found_id_mask |= 1U << found_id;
    return 0;
}

static void strider_ac_test_case_run(struct kunit *test, const char *patterns[], const char *data, int expected_match_count, unsigned int expected_id_mask) {
    struct strider_ac *ac = kunit_alloc_resource(test, strider_ac_test_resource_init, strider_ac_test_resource_free, GFP_KERNEL, NULL);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);
    int ret = 0;
    struct strider_ac_test_target targets[STRIDER_AC_TEST_MAX_TARGETS];
    for (int i = 0; patterns[i]; ++i) {
        targets[i] = (struct strider_ac_test_target){.ac_target = (struct strider_ac_target){.pattern = patterns[i], .pattern_len = strlen(patterns[i])}, .id = i};
        ret = strider_ac_add_target(ac, &targets[i].ac_target, GFP_KERNEL);
        KUNIT_ASSERT_GE(test, ret, 0);
    }
    ret = strider_ac_compile(ac, GFP_KERNEL);
    KUNIT_ASSERT_GE(test, ret, 0);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, data, strlen(data), strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.match_count, expected_match_count);
    KUNIT_EXPECT_EQ(test, info.found_id_mask, expected_id_mask);
}

static void test_basic_matches(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"hello", NULL}, "say hello world", 1, 1U << 0);
}

static void multiple_patterns_multiple_matches(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"world", "test", NULL}, "this is a test, hello world", 2, (1U << 0) | (1U << 1));
}

static void no_match(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"apple", "banana", NULL}, "a grape and a pear", 0, 0);
}

static void empty_data(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"any", NULL}, "", 0, 0);
}

static void pattern_is_prefix_of_another(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"he", "her", NULL}, "ushers", 2, (1U << 0) | (1U << 1));
}

static void pattern_is_suffix_of_another(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"she", "he", NULL}, "she", 2, (1U << 0) | (1U << 1));
}

static void patterns_overlap(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"hers", "she", NULL}, "shers", 2, (1U << 0) | (1U << 1));
}

static void single_failure_fallback(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"abce", "bcd", NULL}, "abcd", 1, 1U << 1);
}

static void multiple_failure_fallbacks(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"ushr", "she", "he", NULL}, "ushe", 2,  (1U << 1) | (1U << 2));
}

static void multiple_outputs_(struct kunit *test) {
    strider_ac_test_case_run(test, (const char *[]){"a", "bca", "ca", NULL}, "bca", 3, (1U << 0) | (1U << 1) | (1U << 2));
}

static struct kunit_case strider_ac_test_cases[] = {
    KUNIT_CASE(single_pattern_single_match),
    KUNIT_CASE(multiple_patterns_multiple_matches),
    KUNIT_CASE(no_match),
    KUNIT_CASE(empty_data),
    KUNIT_CASE(pattern_is_prefix_of_another),
    KUNIT_CASE(pattern_is_suffix_of_another),
    KUNIT_CASE(patterns_overlap),
    KUNIT_CASE(single_failure_fallback),
    KUNIT_CASE(multiple_failure_fallbacks),
    KUNIT_CASE(linked_outputs),
    {}
};

static void strider_ac_test_suite_exit(struct kunit_suite *suite) {
    rcu_barrier();
}

static struct kunit_suite strider_ac_test_suite = {
    .name = "strider_ac",
    .suite_exit = strider_ac_test_suite_exit,
    .test_cases = strider_ac_test_cases,
};

kunit_test_suite(strider_ac_test_suite);

MODULE_LICENSE("GPL");
