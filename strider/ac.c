#include "ac.h"

#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/types.h>

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
    size_t num_nodes;
    u32 max_state_id;
};

struct strider_ac {
    u32 *base;
    u32 *check;
    u32 *failures;
    struct list_head *outputs; // array of lists of struct strider_ac_output
    size_t arr_size;
    struct rcu_head rcu;
    u8 data[];
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
                ++trie->num_nodes;
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

static void strider_ac_trie_reset_state_ids(struct strider_ac_trie *trie) {
    LIST_HEAD(queue);
    list_add_tail(&trie->root->list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, list);
        list_del(&node->list);
        node->state_id = 0;
        const struct strider_ac_transition *tsn;
        list_for_each_entry(tsn, &node->transitions, list)
            list_add_tail(&tsn->next->list, &queue);
    }
    trie->max_state_id = 0;
}

static int strider_ac_transition_cmp(void *priv, const struct list_head *a, const struct list_head *b) {
    const struct strider_ac_transition *tsn_a = list_entry(a, struct strider_ac_transition, list);
    const struct strider_ac_transition *tsn_b = list_entry(b, struct strider_ac_transition, list);
    return tsn_a->byte - tsn_b->byte;
}

static int strider_ac_trie_assign_state_ids(struct strider_ac_trie *trie) {
    size_t num_states = trie->num_nodes;
    size_t arr_size = num_states;

retry_arr_size:;
    arr_size = size_mul(arr_size, 2);
    if (arr_size == SIZE_MAX)
        return -ENOMEM;
    u32 *check = kvcalloc(arr_size, sizeof(*check), GFP_KERNEL);
    if (!check)
        return -ENOMEM;

    trie->root->state_id = 1;
    LIST_HEAD(stack);
    list_add(&trie->root->list, &stack);
    while (!list_empty(&stack)) {
        struct strider_ac_node *node = list_first_entry(&stack, struct strider_ac_node, list);
        list_del(&node->list);

        list_sort(NULL, &node->transitions, strider_ac_transition_cmp);

        u32 base_val = 1;
    retry_base_val:;
        const struct strider_ac_transition *tsn;
        list_for_each_entry(tsn, &node->transitions, list) {
            if (base_val + tsn->byte >= arr_size) {
                strider_ac_trie_reset_state_ids(trie);
                kvfree(check);
                goto retry_arr_size;
            }
            if (check[base_val + tsn->byte] != 0) {
                ++base_val;
                goto retry_base_val;
            }
        }

        node->base_val = base_val;
        list_for_each_entry(tsn, &node->transitions, list) {
            struct strider_ac_node *child = tsn->next;
            child->state_id = base_val + tsn->byte;
            check[child->state_id] = node->state_id;
            list_add(&child->list, &stack);
        }
        if (node->state_id > trie->max_state_id)
            trie->max_state_id = node->state_id;
    }

    kvfree(check);
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
    ++trie->num_nodes;
    int ret = strider_ac_trie_add_targets(trie, get_target, iter_ctx);
    if (ret < 0) {
        strider_ac_trie_destroy(trie);
        return ERR_PTR(ret);
    }
    strider_ac_trie_link_failures(trie);
    ret = strider_ac_trie_assign_state_ids(trie);
    if (ret < 0) {
        strider_ac_trie_destroy(trie);
        return ERR_PTR(ret);
    }

    size_t arr_size = trie->max_state_id + 1;
    // Make sure arr_size is large enough so that the bounds check in the match function is predictable for the root state.
    // For any byte c (0-255), we want base[1] + c < arr_size.
    // This avoids frequent branch mispredictions on worst case input.
    if (arr_size < trie->root->base_val + 256)
        arr_size = trie->root->base_val + 256;
    size_t ac_data_size = array3_size(3, arr_size, sizeof(u32));
    ac_data_size = size_add(ac_data_size, array_size(arr_size, sizeof(struct list_head)));
    if (ac_data_size == SIZE_MAX) {
        strider_ac_trie_destroy(trie);
        return ERR_PTR(-ENOMEM);
    }
    struct strider_ac *ac = kvzalloc(struct_size(ac, data, ac_data_size), GFP_KERNEL);
    if (!ac) {
        strider_ac_trie_destroy(trie);
        return ERR_PTR(-ENOMEM);
    }
    ac->arr_size = arr_size;
    ac->base = (u32 *) ac->data;
    ac->check = ac->base + ac->arr_size;
    ac->failures = ac->check + ac->arr_size;
    ac->outputs = (struct list_head *) (ac->failures + ac->arr_size);
    for (size_t i = 0; i < ac->arr_size; ++i)
        INIT_LIST_HEAD(&ac->outputs[i]);

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
}

static void strider_ac_destroy(struct strider_ac *ac) {
    for (size_t i = 0; i < ac->arr_size; ++i) {
        struct strider_ac_output *out, *tmp;
        list_for_each_entry_safe(out, tmp, &ac->outputs[i], list) {
            list_del(&out->list);
            kfree(out);
        }
    }
    kvfree(ac);
}

static void strider_ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    strider_ac_destroy(ac);
}

void strider_ac_schedule_destroy(struct strider_ac *ac) {
    call_rcu(&ac->rcu, strider_ac_destroy_rcu_cb);
}

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state) {
    state->ac = ac;
    state->ac_state = 1;
}

int strider_ac_match(struct strider_ac_match_state *state, const u8 *data, size_t len,
                     int (*cb)(const struct strider_ac_target *target, size_t pos, void *ctx), void *cb_ctx) {
    const struct strider_ac *ac = state->ac;
    u32 ac_state = state->ac_state;
    int ret = 0;
    for (size_t i = 0; i < len; ++i) {
        for (u32 next; ; ac_state = ac->failures[ac_state]) {
            next = ac->base[ac_state] + data[i];
            if (next < ac->arr_size && ac->check[next] == ac_state) {
                ac_state = next;
                break;
            }
            if (ac_state == 1)
                break;
        }

        for (u32 out = ac_state; out != 1; out = ac->failures[out]) {
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
