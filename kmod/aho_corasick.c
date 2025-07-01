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

// free all resources associated with a node
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

// get or create a transition for a character during build
static struct strider_ac_node *strider_ac_node_get_or_create_next(struct strider_ac_node *node, u8 chr) {
    struct strider_ac_build_transition *bt;

    list_for_each_entry(bt, &node->build_transitions, list) {
        if (bt->chr == chr)
            return bt->next;
    }

    bt = kmalloc(sizeof(*bt), GFP_KERNEL);
    if (!bt)
        return ERR_PTR(-ENOMEM);
    bt->next = strider_ac_node_create();
    if (!bt->next) {
        kfree(bt);
        return ERR_PTR(-ENOMEM);
    }
    bt->chr = chr;
    list_add_tail(&bt->list, &node->build_transitions);
    return bt->next;
}

static int strider_ac_process_input(struct strider_ac_node *root, const struct strider_ac_input *input) {
    struct strider_ac_node *node = root;

    const u8 *pattern = (const u8 *) input->pattern;
    for (size_t i = 0; i < input->len; ++i) {
        node = strider_ac_node_get_or_create_next(node, pattern[i]);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }

    struct strider_ac_output *output = kmalloc(sizeof(*output), GFP_KERNEL);
    if (!output)
        return -ENOMEM;
    output->len = input->len;
    output->priv = input->priv;
    list_add_tail(&output->list, &node->outputs);

    return 0;
}

// build a logical trie using temporary linked-list transitions
static int strider_ac_build_logical_trie(struct strider_ac_node *root, const struct list_head *inputs) {
    const struct strider_ac_input *input;
    int ret = 0;
    list_for_each_entry(input, inputs, list) {
        ret = strider_ac_process_input(root, input);
        if (ret < 0)
            goto out;
    }

out:
    return ret;
}

static int strider_ac_compare_transitions(const void *a, const void *b) {
    const struct strider_ac_transition *ta = a;
    const struct strider_ac_transition *tb = b;
    return ta->chr - tb->chr;
}

// convert the temporary linked-list of transitions into a sorted array
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

// finalize the trie by compacting transitions
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

// find the next transition for a character, called on a node with compacted transitions
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

// find the failure link target for a node, starting from its parent
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

struct strider_ac_automaton * __must_check strider_ac_automaton_build(const struct list_head *inputs) {
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

        strider_ac_node_deinit(node);
        kfree(node);
    }

    kfree(automaton);
}

void strider_ac_match_state_init(struct strider_ac_match_state *state, const struct strider_ac_automaton *automaton) {
    state->cursor = automaton->root;
    state->automaton = automaton;
    state->stream_pos = 0;
}

int strider_ac_automaton_feed(struct strider_ac_match_state *state, const u8 *data, size_t len,
                              int (*cb)(const void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
    if (unlikely(!state->automaton))
        return 0;
    const struct strider_ac_node *root = state->automaton->root;
    for (size_t i = 0; i < len; ++i) {
        // Follow transitions for the current character.
        // If a direct transition fails, traverse failure links
        // until a valid transition is found or the root is reached.
        u8 chr = data[i];
        const struct strider_ac_node *curr_node = state->cursor;
        while (true) {
            const struct strider_ac_node *next = strider_ac_node_find_next(curr_node, chr);
            if (next) {
                state->cursor = next;
                break;
            }
            if (curr_node == root) {
                state->cursor = root;
                break;
            }
            curr_node = curr_node->failure;
        }

        // Inspect each node in the failure chain starting from the final state, to report all matches.
        // This is done to ensure that all patterns that end at the current position are reported,
        // including shorter patterns that are suffixes of longer ones.
        for (const struct strider_ac_node *out_node = state->cursor;; out_node = out_node->failure) {
            if (!list_empty(&out_node->outputs)) {
                const struct strider_ac_output *out;
                list_for_each_entry(out, &out_node->outputs, list) {
                    size_t offset = state->stream_pos + i - out->len + 1;
                    int ret = cb(out->priv, offset, cb_ctx);
                    if (ret != 0) {
                        // callback requested to stop
                        state->stream_pos += i + 1;
                        return ret;
                    }
                }
            }
            if (out_node == root)
                break;
        }
    }

    state->stream_pos += len;
    return 0;
}
