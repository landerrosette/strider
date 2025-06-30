#include "aho_corasick.h"

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/stddef.h>
#include <linux/types.h>

// Represents a finalized, read-only transition.
struct strider_ac_transition {
    u8 chr;
    struct strider_ac_node *next;
};

// Represents a temporary transition used when building the automaton.
struct strider_ac_build_transition {
    struct list_head list;
    u8 chr;
    struct strider_ac_node *next;
};

// Represents a single pattern match output at a given state.
struct strider_ac_output {
    struct list_head list;
    size_t len;
    const void *priv; // caller's private context pointer, returned verbatim on match
};

struct strider_ac_node {
    struct strider_ac_transition *transitions;
    size_t num_transitions;

    struct list_head build_transitions;

    struct strider_ac_node *failure;
    struct list_head outputs;        // list of ac_output
    struct list_head traversal_list; // for build/free traversals
};

struct strider_ac_automaton {
    struct strider_ac_node *root;
};

static struct strider_ac_node *strider_ac_node_create(void) {
    struct strider_ac_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return NULL;
    INIT_LIST_HEAD(&node->build_transitions);
    INIT_LIST_HEAD(&node->outputs);
    INIT_LIST_HEAD(&node->traversal_list);
    return node;
}

static void strider_ac_node_deinit(struct strider_ac_node *node) {
    struct strider_ac_output *out, *tmp;
    list_for_each_entry_safe(out, tmp, &node->outputs, list) {
        list_del(&out->list);
        kfree(out);
    }

    kfree(node->transitions);

    struct strider_ac_build_transition *bt, *bt_tmp;
    list_for_each_entry_safe(bt, bt_tmp, &node->build_transitions, list) {
        list_del(&bt->list);
        kfree(bt);
    }
}

// build a logical trie using flexible, temporary linked lists for state transitions
static int strider_ac_build_logical_trie(struct strider_ac_node *root, struct list_head *inputs) {
    const struct strider_ac_input *input;
    list_for_each_entry(input, inputs, list) {
        struct strider_ac_node *node = root;
        const u8 *pattern = (const u8 *) input->pattern;
        for (size_t i = 0; i < input->len; ++i) {
            u8 chr = pattern[i];
            struct strider_ac_node *next_node = NULL;
            struct strider_ac_build_transition *bt;

            // find existing transition for the current character
            list_for_each_entry(bt, &node->build_transitions, list) {
                if (bt->chr == chr) {
                    next_node = bt->next;
                    break;
                }
            }

            // create a new transition if it doesn't exist
            if (!next_node) {
                bt = kmalloc(sizeof(*bt), GFP_KERNEL);
                if (!bt)
                    return -ENOMEM;
                next_node = strider_ac_node_create();
                if (!next_node) {
                    kfree(bt);
                    return -ENOMEM;
                }
                bt->chr = chr;
                bt->next = next_node;
                list_add_tail(&bt->list, &node->build_transitions);
            }

            node = next_node;
        }

        struct strider_ac_output *output = kmalloc(sizeof(*output), GFP_KERNEL);
        if (!output)
            return -ENOMEM;
        output->len = input->len;
        output->priv = input->priv;
        list_add_tail(&output->list, &node->outputs);
    }

    return 0;
}

static int strider_ac_compare_transitions(const void *a, const void *b) {
    const struct strider_ac_transition *ta = a;
    const struct strider_ac_transition *tb = b;
    return ta->chr - tb->chr;
}

// sort the transitions and convert the temporary linked list into a contiguous array
static int strider_ac_node_compact_transitions(struct strider_ac_node *node) {
    size_t count = 0;
    struct strider_ac_build_transition *bt;
    list_for_each_entry(bt, &node->build_transitions, list)
        ++count;

    if (count > 0) {
        node->transitions = kcalloc(count, sizeof(*node->transitions), GFP_KERNEL);
        if (!node->transitions)
            return -ENOMEM;
        struct strider_ac_build_transition *tmp;
        size_t i = 0;
        // copy transitions from the temporary list to the final array
        list_for_each_entry_safe(bt, tmp, &node->build_transitions, list) {
            node->transitions[i].chr = bt->chr;
            node->transitions[i].next = bt->next;
            ++i;
            list_del(&bt->list);
            kfree(bt);
        }
        node->num_transitions = count;
        sort(node->transitions, count, sizeof(*node->transitions), strider_ac_compare_transitions, NULL);
    }

    return 0;
}

static int strider_ac_finalize_trie(struct strider_ac_node *root) {
    LIST_HEAD(queue);
    int ret = 0;
    list_add_tail(&root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);
        ret = strider_ac_node_compact_transitions(node);
        if (ret < 0)
            goto fail;
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct strider_ac_node *child = node->transitions[i].next;
            list_add_tail(&child->traversal_list, &queue);
        }
    }

out:
    WARN_ON_ONCE(!list_empty(&queue));
    return ret;

fail:
    struct strider_ac_node *node, *tmp;
    // clear the in-flight traversal queue
    list_for_each_entry_safe(node, tmp, &queue, traversal_list)
        list_del(&node->traversal_list);
    goto out;
}

static struct strider_ac_node *strider_ac_node_find_next(const struct strider_ac_node *node, u8 chr) {
    size_t left = 0, right = node->num_transitions;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (node->transitions[mid].chr < chr)
            left = mid + 1;
        else
            right = mid;
    }
    if (left < node->num_transitions && node->transitions[left].chr == chr)
        return node->transitions[left].next;
    return NULL;
}

static struct strider_ac_node *strider_ac_node_find_failure_target(const struct strider_ac_node *parent, u8 chr) {
    const struct strider_ac_node *node;
    for (node = parent->failure; node != node->failure; node = node->failure) {
        struct strider_ac_node *target = strider_ac_node_find_next(node, chr);
        if (target)
            return target;
    }
    // node is now root
    return strider_ac_node_find_next(node, chr);
}

static void strider_ac_build_failure_links(struct strider_ac_node *root) {
    root->failure = root;
    LIST_HEAD(queue);
    // point root's children's failure links to root
    for (size_t i = 0; i < root->num_transitions; ++i) {
        struct strider_ac_node *child = root->transitions[i].next;
        child->failure = root;
        list_add_tail(&child->traversal_list, &queue); // enqueue the child for BFS traversal
    }

    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list); // dequeue
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct strider_ac_node *child = node->transitions[i].next;
            struct strider_ac_node *failure_target =
                    strider_ac_node_find_failure_target(node, node->transitions[i].chr);
            child->failure = failure_target ? failure_target : root;
            list_add_tail(&child->traversal_list, &queue); // enqueue the child
        }
    }
}

struct strider_ac_automaton * __must_check strider_ac_automaton_build(struct list_head *inputs) {
    struct strider_ac_automaton *automaton = kmalloc(sizeof(*automaton), GFP_KERNEL);
    int ret = 0;
    if (!automaton) {
        ret = -ENOMEM;
        goto fail;
    }
    automaton->root = strider_ac_node_create();
    if (!automaton->root) {
        kfree(automaton);
        ret = -ENOMEM;
        goto fail;
    }
    automaton->root->failure = automaton->root;

    ret = strider_ac_build_logical_trie(automaton->root, inputs);
    if (ret < 0)
        goto fail_automaton_free;

    ret = strider_ac_finalize_trie(automaton->root);
    if (ret < 0)
        goto fail_automaton_free;

    strider_ac_build_failure_links(automaton->root);

    return automaton;

fail_automaton_free:
    strider_ac_automaton_free(automaton);
fail:
    return ERR_PTR(ret);
}

void strider_ac_automaton_free(struct strider_ac_automaton *automaton) {
    if (!automaton)
        return;
    if (!automaton->root) {
        kfree(automaton);
        return;
    }

    LIST_HEAD(queue);
    list_add_tail(&automaton->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list); // dequeue the current node

        // enqueue all children for the next cleanup iteration
        if (node->transitions) {
            for (size_t i = 0; i < node->num_transitions; ++i)
                list_add_tail(&node->transitions[i].next->traversal_list, &queue);
        } else {
            struct strider_ac_build_transition *bt;
            list_for_each_entry(bt, &node->build_transitions, list)
                list_add_tail(&bt->next->traversal_list, &queue);
        }

        strider_ac_node_deinit(node); // release the current node's resources
        kfree(node);
    }

    WARN_ON_ONCE(!list_empty(&queue));

    kfree(automaton);
}

void strider_ac_match_state_init(const struct strider_ac_automaton *automaton, struct strider_ac_match_state *state) {
    state->cursor = automaton->root;
    state->stream_pos = 0;
}

int strider_ac_automaton_feed(struct strider_ac_match_state *state, const u8 *data, size_t len,
                              int (*cb)(const void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
}
