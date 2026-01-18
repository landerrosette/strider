// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2025-2026 landerrosette
 */

#include "ac.h"

#include <linux/bitmap.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/types.h>

#define STRIDER_AC_ROOT_STATE_ID 1

struct strider_ac_output {
    struct list_head list;
    const struct strider_ac_target *target;
};

struct strider_ac_node {
    struct list_head transitions;
    struct list_head outputs;
    struct strider_ac_node *failure;
    u32 state_id;
    u32 base_val;
    struct list_head list; // for traversal
};

struct strider_ac_transition {
    struct list_head list;
    u8 byte;
    struct strider_ac_node *next;
};

struct strider_ac_trie {
    struct strider_ac_node *root;
    u32 num_nodes;
    u32 max_base_val;
};

struct strider_ac {
    u32 *base;
    u32 *check;
    u32 *failures;
    struct list_head *outputs; // array of lists of struct strider_ac_output
    u32 arr_size;
    struct rcu_head rcu;
};

static struct strider_ac_node *strider_ac_node_create(void) {
    struct strider_ac_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return NULL;
    INIT_LIST_HEAD(&node->transitions);
    INIT_LIST_HEAD(&node->outputs);
    return node;
}

static struct strider_ac_node *strider_ac_node_find_next(const struct strider_ac_node *node, u8 byte) {
    const struct strider_ac_transition *tsn;
    list_for_each_entry(tsn, &node->transitions, list) {
        if (tsn->byte == byte)
            return tsn->next;
    }
    return NULL;
}

static struct strider_ac_node *strider_ac_node_add_child(struct strider_ac_node *node, u8 byte) {
    struct strider_ac_transition *tsn = kmalloc(sizeof(*tsn), GFP_KERNEL);
    if (!tsn)
        return NULL;
    tsn->next = strider_ac_node_create();
    if (!tsn->next) {
        kfree(tsn);
        return NULL;
    }
    tsn->byte = byte;
    list_add(&tsn->list, &node->transitions);
    return tsn->next;
}

static void strider_ac_trie_destroy(struct strider_ac_trie *trie) {
    LIST_HEAD(queue);
    list_add_tail(&trie->root->list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, list);
        list_del(&node->list);
        {
            struct strider_ac_output *out, *tmp;
            list_for_each_entry_safe(out, tmp, &node->outputs, list) {
                list_del(&out->list);
                kfree(out);
            }
        }
        {
            struct strider_ac_transition *tsn, *tmp;
            list_for_each_entry_safe(tsn, tmp, &node->transitions, list) {
                list_add_tail(&tsn->next->list, &queue);
                list_del(&tsn->list);
                kfree(tsn);
            }
        }
        kfree(node);
    }
    kfree(trie);
}

static int strider_ac_trie_add_targets(struct strider_ac_trie *trie,
                                       const struct strider_ac_target *(*get_target)(void *ctx), void *iter_ctx) {
    for (const struct strider_ac_target *target; (target = get_target(iter_ctx));) {
        struct strider_ac_node *node = trie->root;
        for (size_t i = 0; i < target->pattern_len; ++i) {
            struct strider_ac_node *child = strider_ac_node_find_next(node, target->pattern[i]);
            if (!child) {
                child = strider_ac_node_add_child(node, target->pattern[i]);
                if (!child)
                    return -ENOMEM;
                if (check_add_overflow(trie->num_nodes, 1, &trie->num_nodes) != 0)
                    return -ENOMEM;
            }
            node = child;
        }
        if (node != trie->root) {
            struct strider_ac_output *out = kmalloc(sizeof(*out), GFP_KERNEL);
            if (!out)
                return -ENOMEM;
            out->target = target;
            list_add(&out->list, &node->outputs);
        }
    }
    return 0;
}

static void strider_ac_trie_link_failures(struct strider_ac_trie *trie) {
    trie->root->failure = trie->root;
    LIST_HEAD(queue);
    const struct strider_ac_transition *tsn;
    list_for_each_entry(tsn, &trie->root->transitions, list) {
        tsn->next->failure = trie->root;
        list_add_tail(&tsn->next->list, &queue);
    }
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, list);
        list_del(&node->list);
        list_for_each_entry(tsn, &node->transitions, list) {
            struct strider_ac_node *child = tsn->next;
            for (const struct strider_ac_node *f = node->failure; ; f = f->failure) {
                struct strider_ac_node *fnext = strider_ac_node_find_next(f, tsn->byte);
                if (fnext) {
                    child->failure = fnext;
                    break;
                }
                if (f == trie->root) {
                    child->failure = trie->root;
                    break;
                }
            }
            list_add_tail(&child->list, &queue);
        }
    }
}

static int strider_ac_transition_cmp(void *priv, const struct list_head *a, const struct list_head *b) {
    const struct strider_ac_transition *tsn_a = list_entry(a, struct strider_ac_transition, list);
    const struct strider_ac_transition *tsn_b = list_entry(b, struct strider_ac_transition, list);
    return tsn_a->byte - tsn_b->byte;
}

static int strider_ac_trie_assign_state_ids(struct strider_ac_trie *trie) {
    u32 arr_size;
    if (check_add_overflow(trie->num_nodes, 256, &arr_size) != 0)
        return -ENOMEM;
    unsigned long *occupied = bitmap_zalloc(arr_size, GFP_KERNEL);
    if (!occupied)
        return -ENOMEM;

    trie->root->state_id = STRIDER_AC_ROOT_STATE_ID;
    set_bit(STRIDER_AC_ROOT_STATE_ID, occupied);
    LIST_HEAD(stack);
    list_add(&trie->root->list, &stack);

    while (!list_empty(&stack)) {
        struct strider_ac_node *node = list_first_entry(&stack, struct strider_ac_node, list);
        list_del(&node->list);
        if (list_empty(&node->transitions))
            continue;
        list_sort(NULL, &node->transitions, strider_ac_transition_cmp);

        u8 first_byte = list_first_entry(&node->transitions, struct strider_ac_transition, list)->byte;
        u8 last_byte = list_last_entry(&node->transitions, struct strider_ac_transition, list)->byte;
        u32 slot = first_byte + 1;
    retry:
        slot = find_next_zero_bit(occupied, arr_size, slot); // arr_size shall be >= 256 so base_val will not underflow
        u32 base_val = slot - first_byte;
        if (base_val + last_byte >= arr_size) {
            u32 new_arr_size;
            if (check_mul_overflow(arr_size, 2, &new_arr_size) != 0) {
                bitmap_free(occupied);
                return -ENOMEM;
            }
            unsigned long *new_occupied = bitmap_zalloc(new_arr_size, GFP_KERNEL);
            if (!new_occupied) {
                bitmap_free(occupied);
                return -ENOMEM;
            }
            bitmap_copy(new_occupied, occupied, arr_size);
            bitmap_free(occupied);
            occupied = new_occupied;
            arr_size = new_arr_size;
            goto retry;
        }
        const struct strider_ac_transition *tsn;
        list_for_each_entry(tsn, &node->transitions, list) {
            if (test_bit(base_val + tsn->byte, occupied)) {
                ++slot;
                goto retry;
            }
        }

        node->base_val = base_val;
        if (node->base_val > trie->max_base_val)
            trie->max_base_val = node->base_val;
        list_for_each_entry(tsn, &node->transitions, list) {
            struct strider_ac_node *child = tsn->next;
            child->state_id = base_val + tsn->byte;
            set_bit(child->state_id, occupied);
            list_add(&child->list, &stack);
        }
    }

    bitmap_free(occupied);
    return 0;
}

struct strider_ac *strider_ac_build(const struct strider_ac_target *(*get_target)(void *ctx), void *iter_ctx) {
    struct strider_ac_node *root = strider_ac_node_create();
    if (!root)
        return ERR_PTR(-ENOMEM);
    struct strider_ac_trie *trie = kzalloc(sizeof(*trie), GFP_KERNEL);
    if (!trie) {
        kfree(root);
        return ERR_PTR(-ENOMEM);
    }
    trie->root = root;
    trie->num_nodes = 1;
    int ret = strider_ac_trie_add_targets(trie, get_target, iter_ctx);
    if (ret < 0)
        goto fail;
    strider_ac_trie_link_failures(trie);
    ret = strider_ac_trie_assign_state_ids(trie);
    if (ret < 0)
        goto fail;

    u32 arr_size;
    // make arrays large enough to eliminate match-time bounds check
    if (check_add_overflow(trie->max_base_val, 256, &arr_size) != 0) {
        ret = -ENOMEM;
        goto fail;
    }
    struct strider_ac *ac = kmalloc(sizeof(*ac), GFP_KERNEL);
    if (!ac) {
        ret = -ENOMEM;
        goto fail;
    }
    ac->base = kvcalloc(arr_size, sizeof(*ac->base), GFP_KERNEL);
    if (!ac->base) {
        ret = -ENOMEM;
        goto fail_kfree_ac;
    }
    ac->check = kvcalloc(arr_size, sizeof(*ac->check), GFP_KERNEL);
    if (!ac->check) {
        ret = -ENOMEM;
        goto fail_kvfree_base;
    }
    ac->failures = kvcalloc(arr_size, sizeof(*ac->failures), GFP_KERNEL);
    if (!ac->failures) {
        ret = -ENOMEM;
        goto fail_kvfree_check;
    }
    ac->outputs = kvcalloc(arr_size, sizeof(*ac->outputs), GFP_KERNEL);
    if (!ac->outputs) {
        ret = -ENOMEM;
        goto fail_kvfree_failures;
    }
    for (u32 i = 0; i < arr_size; ++i)
        INIT_LIST_HEAD(&ac->outputs[i]);
    ac->arr_size = arr_size;

    LIST_HEAD(queue);
    list_add_tail(&trie->root->list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, list);
        list_del(&node->list);
        ac->base[node->state_id] = node->base_val;
        ac->failures[node->state_id] = node->failure->state_id;
        list_replace_init(&node->outputs, &ac->outputs[node->state_id]); // steal list of outputs

        const struct strider_ac_transition *tsn;
        list_for_each_entry(tsn, &node->transitions, list) {
            struct strider_ac_node *child = tsn->next;
            ac->check[child->state_id] = node->state_id;
            list_add_tail(&child->list, &queue);
        }
    }

    strider_ac_trie_destroy(trie);
    return ac;

fail_kvfree_failures:
    kvfree(ac->failures);
fail_kvfree_check:
    kvfree(ac->check);
fail_kvfree_base:
    kvfree(ac->base);
fail_kfree_ac:
    kfree(ac);
fail:
    strider_ac_trie_destroy(trie);
    return ERR_PTR(ret);
}

static void strider_ac_destroy(struct strider_ac *ac) {
    for (u32 i = 0; i < ac->arr_size; ++i) {
        struct strider_ac_output *out, *tmp;
        list_for_each_entry_safe(out, tmp, &ac->outputs[i], list) {
            list_del(&out->list);
            kfree(out);
        }
    }
    kvfree(ac->outputs);
    kvfree(ac->failures);
    kvfree(ac->check);
    kvfree(ac->base);
    kfree(ac);
}

static void strider_ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    strider_ac_destroy(ac);
}

void strider_ac_destroy_rcu(struct strider_ac *ac) {
    call_rcu(&ac->rcu, strider_ac_destroy_rcu_cb);
}

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state) {
    state->ac = ac;
    state->ac_state = STRIDER_AC_ROOT_STATE_ID;
}

int strider_ac_match(struct strider_ac_match_state *state, const u8 *data, size_t len,
                     int (*cb)(const struct strider_ac_target *target, size_t pos, void *ctx), void *cb_ctx) {
    const struct strider_ac *ac = state->ac;
    u32 ac_state = state->ac_state;
    int ret = 0;
    for (size_t i = 0; i < len; ++i) {
        for (u32 next; ; ac_state = ac->failures[ac_state]) {
            next = ac->base[ac_state] + data[i];
            if (ac->check[next] == ac_state) {
                ac_state = next;
                break;
            }
            if (ac_state == STRIDER_AC_ROOT_STATE_ID)
                break;
        }

        for (u32 out = ac_state; out != STRIDER_AC_ROOT_STATE_ID; out = ac->failures[out]) {
            if (!list_empty(&ac->outputs[out])) {
                const struct strider_ac_output *output;
                list_for_each_entry(output, &ac->outputs[out], list) {
                    ret = cb(output->target, i, cb_ctx);
                    if (ret != 0)
                        goto out;
                }
            }
        }
    }
out:
    state->ac_state = ac_state;
    return ret;
}
