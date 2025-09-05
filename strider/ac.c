#include "ac.h"

#include <linux/bsearch.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/types.h>

// Represents a finalized, read-only transition.
struct strider_ac_transition {
    struct strider_ac_node *next;
    u8 ch;
};

// Represents a temporary transition used during trie construction.
struct strider_ac_transition_linked {
    struct list_head list;
    struct strider_ac_node *next;
    u8 ch;
};

struct strider_ac_node {
    struct strider_ac_transition *transitions;
    size_t num_transitions;
    struct strider_ac_node *failure;
    struct list_head outputs; // list of struct strider_ac_target
    struct strider_ac_node *output_link;
    struct list_head linked_transitions;
    struct list_head traversal_list;
};

struct strider_ac {
    struct strider_ac_node *root;
    struct rcu_head rcu;
};

static struct strider_ac_node *strider_ac_node_create(gfp_t gfp_mask) {
    struct strider_ac_node *node = kzalloc(sizeof(*node), gfp_mask);
    if (!node) return NULL;
    INIT_LIST_HEAD(&node->outputs);
    INIT_LIST_HEAD(&node->linked_transitions);
    INIT_LIST_HEAD(&node->traversal_list);
    return node;
}

static void strider_ac_node_destroy(struct strider_ac_node *node) {
    kfree(node->transitions);
    struct strider_ac_transition_linked *tsn, *tmp;
    list_for_each_entry_safe(tsn, tmp, &node->linked_transitions, list) {
        list_del(&tsn->list);
        kfree(tsn);
    }
    kfree(node);
}

static void strider_ac_destroy(struct strider_ac *ac) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);

        for (size_t i = 0; i < node->num_transitions; ++i)
            list_add_tail(&node->transitions[i].next->traversal_list, &queue);
        struct strider_ac_transition_linked *tsn;
        list_for_each_entry(tsn, &node->linked_transitions, list)
            list_add_tail(&tsn->next->traversal_list, &queue);

        strider_ac_node_destroy(node);
    }
    kfree(ac);
}

static void strider_ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    strider_ac_destroy(ac);
}

static struct strider_ac_node *strider_ac_transition_build(struct strider_ac_node *node, u8 ch, gfp_t gfp_mask) {
    struct strider_ac_transition_linked *tsn;

    list_for_each_entry(tsn, &node->linked_transitions, list) {
        if (tsn->ch == ch)
            return tsn->next;
    }

    tsn = kmalloc(sizeof(*tsn), gfp_mask);
    if (!tsn)
        return ERR_PTR(-ENOMEM);
    tsn->next = strider_ac_node_create(gfp_mask);
    if (!tsn->next) {
        kfree(tsn);
        return ERR_PTR(-ENOMEM);
    }
    tsn->ch = ch;
    list_add_tail(&tsn->list, &node->linked_transitions);
    return tsn->next;
}

static int strider_ac_transition_compare(const void *a, const void *b) {
    const struct strider_ac_transition *ta = a;
    const struct strider_ac_transition *tb = b;
    return ta->ch - tb->ch;
}

// convert the temporary linked-list of transitions into a sorted array
static int strider_ac_transitions_finalize(struct strider_ac_node *node, gfp_t gfp_mask) {
    size_t count = 0;
    struct strider_ac_transition_linked *tsn;
    list_for_each_entry(tsn, &node->linked_transitions, list)
        ++count;

    if (count > 0) {
        node->transitions = kmalloc_array(count, sizeof(*node->transitions), gfp_mask);
        if (!node->transitions)
            return -ENOMEM;
        struct strider_ac_transition_linked *tmp;
        size_t i = 0;
        // copy transitions from the temporary list to the final array
        list_for_each_entry_safe(tsn, tmp, &node->linked_transitions, list) {
            node->transitions[i].next = tsn->next;
            node->transitions[i].ch = tsn->ch;
            ++i;
            list_del(&tsn->list);
            kfree(tsn);
        }
        BUG_ON(i != count);
        node->num_transitions = count;
        sort(node->transitions, count, sizeof(*node->transitions), strider_ac_transition_compare, NULL);
    }

    return 0;
}

// called on a node with finalized transitions
static struct strider_ac_node *strider_ac_find_next_node(const struct strider_ac_node *node, u8 ch) {
    struct strider_ac_transition key = {.ch = ch};
    const struct strider_ac_transition *tsn = bsearch(&key, node->transitions, node->num_transitions,
                                                      sizeof(*node->transitions), strider_ac_transition_compare);
    return tsn ? tsn->next : NULL;
}

static struct strider_ac_node *strider_ac_find_failure_node(const struct strider_ac_node *parent, u8 ch) {
    const struct strider_ac_node *node;
    for (node = parent->failure; node != node->failure; node = node->failure) {
        struct strider_ac_node *next = strider_ac_find_next_node(node, ch);
        if (next)
            return next;
    }
    // node is now root
    return strider_ac_find_next_node(node, ch);
}

static void strider_ac_finalize(struct strider_ac_node *root) {
    root->failure = root;
    LIST_HEAD(queue);
    // point root's children's failure links to root
    for (size_t i = 0; i < root->num_transitions; ++i) {
        struct strider_ac_node *child = root->transitions[i].next;
        child->failure = root;
        list_add_tail(&child->traversal_list, &queue);
    }
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct strider_ac_node *child = node->transitions[i].next;
            struct strider_ac_node *failure_node = strider_ac_find_failure_node(node, node->transitions[i].ch);
            child->failure = failure_node ? failure_node : root;
            child->output_link = list_empty(&child->failure->outputs) ? child->failure->output_link : child->failure;
            list_add_tail(&child->traversal_list, &queue);
        }
    }
}

struct strider_ac *strider_ac_init(gfp_t gfp_mask) {
    struct strider_ac *ac = kmalloc(sizeof(*ac), gfp_mask);
    if (!ac)
        return ERR_PTR(-ENOMEM);
    ac->root = strider_ac_node_create(gfp_mask);
    if (!ac->root) {
        kfree(ac);
        return ERR_PTR(-ENOMEM);
    }
    return ac;
}

void strider_ac_schedule_destroy(struct strider_ac *ac) {
    call_rcu(&ac->rcu, strider_ac_destroy_rcu_cb);
}

int strider_ac_add_target(struct strider_ac *ac, struct strider_ac_target *target, gfp_t gfp_mask) {
    struct strider_ac_node *node = ac->root;
    for (size_t i = 0; i < target->pattern_len; ++i) {
        node = strider_ac_transition_build(node, target->pattern[i], gfp_mask);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }
    list_add(&target->list, &node->outputs);
    return 0;
}

int strider_ac_compile(struct strider_ac *ac, gfp_t gfp_mask) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);
        int ret = strider_ac_transitions_finalize(node, gfp_mask);
        if (ret < 0) {
            struct strider_ac_node *tmp;
            // clear the in-flight traversal queue
            list_for_each_entry_safe(node, tmp, &queue, traversal_list)
                list_del(&node->traversal_list);
            return ret;
        }
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct strider_ac_node *child = node->transitions[i].next;
            list_add_tail(&child->traversal_list, &queue);
        }
    }
    strider_ac_finalize(ac->root);
    return 0;
}

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state) {
    state->cursor = ac->root;
}

int strider_ac_match(struct strider_ac_match_state *state, const u8 *data, size_t len,
                     int (*cb)(const struct strider_ac_target *target, size_t pos, void *ctx), void *cb_ctx) {
    const struct strider_ac_node *cursor = state->cursor;
    int ret = 0;
    for (size_t i = 0; i < len; ++i) {
        for (const struct strider_ac_node *node = cursor; ; node = node->failure) {
            const struct strider_ac_node *next = strider_ac_find_next_node(node, data[i]);
            if (next) {
                cursor = next;
                break;
            }
            if (node->failure == node) {
                // reached root
                cursor = node;
                break;
            }
        }

        for (const struct strider_ac_node *node = cursor; node; node = node->output_link) {
            if (!list_empty(&node->outputs)) {
                const struct strider_ac_target *target;
                list_for_each_entry(target, &node->outputs, list) {
                    ret = cb(target, i, cb_ctx);
                    if (ret != 0)
                        goto out;
                }
            }
        }
    }
out:
    state->cursor = cursor;
    return ret;
}
