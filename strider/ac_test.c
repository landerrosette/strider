#include "ac.h"

#include <kunit/resource.h>
#include <kunit/test.h>
#include <linux/bitops.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/string.h>

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

static int strider_ac_test_match_cb(const struct strider_ac_target *ac_target, size_t pos, void *ctx) {
    struct strider_ac_test_match_info *info = ctx;
    ++info->match_count;
    int found_id = container_of(ac_target, struct strider_ac_test_target, ac_target)->id;
    KUNIT_ASSERT_LT(info->test, found_id, STRIDER_AC_TEST_MAX_TARGETS);
    info->found_id_mask |= 1U << found_id;
    return 0;
}

static void strider_ac_test_case_run(struct kunit *test, const char *patterns[], const char *data,
                                     int expected_match_count, unsigned int expected_id_mask) {
    struct strider_ac *ac = kunit_alloc_resource(test, strider_ac_test_resource_init, strider_ac_test_resource_free,
                                                 GFP_KERNEL, NULL);
    KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ac);
    int ret = 0;
    struct strider_ac_test_target targets[STRIDER_AC_TEST_MAX_TARGETS];
    for (int i = 0; patterns[i]; ++i) {
        targets[i] = (struct strider_ac_test_target){
            .ac_target = (struct strider_ac_target){
                .pattern = (const u8 *) patterns[i], .pattern_len = strlen(patterns[i])
            },
            .id = i,
        };
        ret = strider_ac_add_target(ac, &targets[i].ac_target, GFP_KERNEL);
        KUNIT_ASSERT_GE(test, ret, 0);
    }
    ret = strider_ac_compile(ac, GFP_KERNEL);
    KUNIT_ASSERT_GE(test, ret, 0);

    struct strider_ac_test_match_info info = {.test = test};
    struct strider_ac_match_state state;
    strider_ac_match_init(ac, &state);
    strider_ac_match(&state, (const u8 *) data, strlen(data), strider_ac_test_match_cb, &info);
    KUNIT_EXPECT_EQ(test, info.match_count, expected_match_count);
    KUNIT_EXPECT_EQ(test, info.found_id_mask, expected_id_mask);
}

static void test_classic_prefix_suffix_overlap(struct kunit *test) {
    strider_ac_test_case_run(test,
                             (const char *[]){"he", "she", "his", "hers", NULL},
                             "ahishers",
                             4,
                             1U << 0 | 1U << 1 | 1U << 2 | 1U << 3);
}

static void test_multi_overlap_sequences(struct kunit *test) {
    strider_ac_test_case_run(test,
                             (const char *[]){"ana", "nana", "banana", NULL},
                             "bananana",
                             6,
                             1U << 0 | 1U << 1 | 1U << 2);
}

static void test_repeated_char_overlaps(struct kunit *test) {
    strider_ac_test_case_run(test,
                             (const char *[]){"a", "aa", "aaa", NULL},
                             "aaaaa",
                             12,
                             1U << 0 | 1U << 1 | 1U << 2);
}

static void test_shared_prefix_varied_lengths(struct kunit *test) {
    strider_ac_test_case_run(test,
                             (const char *[]){"a", "ab", "bab", "bc", "bca", "c", "caa", NULL},
                             "abccab",
                             7,
                             1U << 0 | 1U << 1 | 1U << 3 | 1U << 5);
}

static void test_nested_prefix_suffix_outputs(struct kunit *test) {
    strider_ac_test_case_run(test,
                             (const char *[]){"abc", "abcd", "bc", NULL},
                             "zabcabcd",
                             5,
                             1U << 0 | 1U << 1 | 1U << 2);
}

static void test_no_match_result(struct kunit *test) {
    strider_ac_test_case_run(test,
                             (const char *[]){"hello", "world", NULL},
                             "well, hi there",
                             0,
                             0);
}

static struct kunit_case strider_ac_test_cases[] = {
    KUNIT_CASE(test_classic_prefix_suffix_overlap),
    KUNIT_CASE(test_multi_overlap_sequences),
    KUNIT_CASE(test_repeated_char_overlaps),
    KUNIT_CASE(test_shared_prefix_varied_lengths),
    KUNIT_CASE(test_nested_prefix_suffix_outputs),
    KUNIT_CASE(test_no_match_result),
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
