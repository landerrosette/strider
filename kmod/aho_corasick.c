#include "aho_corasick.h"

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/stddef.h>
#include <linux/types.h>

// Represents a single pattern match output at a given state.
struct ac_output {
    struct list_head list;
    size_t len;
    const void *priv; // caller's private context pointer, returned verbatim on match
};

// Represents a finalized, read-only transition.
struct ac_transition {
    u8 chr;
    struct ac_node *next;
};

// Represents a temporary transition used when building the automaton.
struct ac_build_transition {
    struct list_head list;
    u8 chr;
    struct ac_node *next;
};

struct ac_node {
    struct ac_transition *transitions;
    size_t num_transitions;

    struct list_head build_transitions;

    struct ac_node *failure;
    struct list_head outputs;        // list of ac_output
    struct list_head traversal_list; // for build/free traversals
};

struct ac_automaton {
    struct ac_node *root;
};

static struct ac_node *ac_node_create(void) {
    struct ac_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return NULL;
    INIT_LIST_HEAD(&node->build_transitions);
    INIT_LIST_HEAD(&node->outputs);
    INIT_LIST_HEAD(&node->traversal_list);
    return node;
}

static void ac_node_deinit(struct ac_node *node) {
    struct ac_output *out, *tmp;
    list_for_each_entry_safe(out, tmp, &node->outputs, list) {
        list_del(&out->list);
        kfree(out);
    }

    kfree(node->transitions);

    struct ac_build_transition *bt, *bt_tmp;
    list_for_each_entry_safe(bt, bt_tmp, &node->build_transitions, list) {
        list_del(&bt->list);
        kfree(bt);
    }
}

static struct ac_node *ac_node_find_next(const struct ac_node *node, u8 chr) {
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

static int compare_transitions(const void *a, const void *b) {
    const struct ac_transition *ta = a;
    const struct ac_transition *tb = b;
    return ta->chr - tb->chr;
}

// build a logical Trie using flexible, temporary linked lists for state transitions
static int build_logical_trie(struct ac_node *root, struct list_head *inputs_head) {
    const struct ac_input *input;
    list_for_each_entry(input, inputs_head, list) {
        struct ac_node *node = root;
        const u8 *pattern = (const u8 *) input->pattern;
        for (size_t i = 0; i < input->len; ++i) {
            u8 chr = pattern[i];
            struct ac_node *next_node = NULL;
            struct ac_build_transition *bt;

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
                next_node = ac_node_create();
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

        struct ac_output *output = kmalloc(sizeof(*output), GFP_KERNEL);
        if (!output)
            return -ENOMEM;
        output->len = input->len;
        output->priv = input->priv;
        list_add_tail(&output->list, &node->outputs);
    }

    return 0;
}

// convert the temporary transition lists into sorted, contiguous arrays, then compute failure links
static int finalize_trie_and_build_failures(struct ac_node *root) {
    LIST_HEAD(queue);
    list_add_tail(&root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list); // dequeue the current node

        /* 1. Finalize the transitions for the current node. */

        struct ac_build_transition *bt;
        size_t count = 0;
        list_for_each_entry(bt, &node->build_transitions, list)
            ++count;

        if (count > 0) {
            node->num_transitions = count;
            node->transitions = kcalloc(count, sizeof(*node->transitions), GFP_KERNEL);
            if (!node->transitions)
                goto fail;
            size_t i = 0;
            struct ac_build_transition *tmp;
            // copy transitions from the temporary list to the final array
            list_for_each_entry_safe(bt, tmp, &node->build_transitions, list) {
                node->transitions[i].chr = bt->chr;
                node->transitions[i].next = bt->next;
                ++i;
                list_del(&bt->list);
                kfree(bt);
            }
            sort(node->transitions, count, sizeof(*node->transitions), compare_transitions, NULL);
        }

        /* 2. Compute failure links for all children and enqueue them. */

        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct ac_node *child = node->transitions[i].next;
            u8 chr = node->transitions[i].chr;
            if (node == root) {
                child->failure = root;
            } else {
                const struct ac_node *f = node->failure;
                struct ac_node *f_next = NULL;
                for (;; f = f->failure) {
                    f_next = ac_node_find_next(f, chr);
                    if (f_next) {
                        child->failure = f_next;
                        break;
                    }
                    if (f == root) {
                        child->failure = root;
                        break;
                    }
                }
            }
            list_add_tail(&child->traversal_list, &queue); // enqueue the child
        }
    }

    WARN_ON_ONCE(!list_empty(&queue));

    return 0;

fail:
    struct ac_node *node, *tmp;
    // clear the in-flight traversal queue
    list_for_each_entry_safe(node, tmp, &queue, traversal_list)
        list_del(&node->traversal_list);
    return -ENOMEM;
}

static int ac_report_matches(const struct ac_match_state *state,
                             int (*cb)(const void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
    int ret = 0;
    if (!cb) return ret;

    // traverse the failure links chain to find all patterns ending at this position
    for (const struct ac_node *node = state->current_state;; node = node->failure) {
        const struct ac_output *out;
        list_for_each_entry(out, &node->outputs, list) {
            size_t match_offset = state->stream_pos - out->len;
            ret = cb(out->priv, match_offset, cb_ctx);
            if (ret != 0)
                return ret; // immediately exit and propagate the signal
        }
        if (node == node->failure) // reached the root node
            break;
    }

    return ret;
}

struct ac_automaton * __must_check ac_automaton_build(struct list_head *inputs_head) {
    struct ac_automaton *automaton = kmalloc(sizeof(*automaton), GFP_KERNEL);
    int ret = 0;
    if (!automaton) {
        ret = -ENOMEM;
        goto fail;
    }
    automaton->root = ac_node_create();
    if (!automaton->root) {
        kfree(automaton);
        ret = -ENOMEM;
        goto fail;
    }
    automaton->root->failure = automaton->root;

    ret = build_logical_trie(automaton->root, inputs_head);
    if (ret < 0)
        goto fail_automaton_free;

    ret = finalize_trie_and_build_failures(automaton->root);
    if (ret < 0)
        goto fail_automaton_free;

    return automaton;

fail_automaton_free:
    ac_automaton_free(automaton);
fail:
    return ERR_PTR(ret);
}

void ac_automaton_free(struct ac_automaton *automaton) {
    if (!automaton)
        return;
    if (!automaton->root) {
        kfree(automaton);
        return;
    }

    LIST_HEAD(queue);
    list_add_tail(&automaton->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list); // dequeue the current node

        // enqueue all children for the next cleanup iteration
        if (node->transitions) {
            for (size_t i = 0; i < node->num_transitions; ++i)
                list_add_tail(&node->transitions[i].next->traversal_list, &queue);
        } else {
            struct ac_build_transition *bt;
            list_for_each_entry(bt, &node->build_transitions, list)
                list_add_tail(&bt->next->traversal_list, &queue);
        }

        ac_node_deinit(node); // release the current node's resources
        kfree(node);
    }

    WARN_ON_ONCE(!list_empty(&queue));

    kfree(automaton);
}

void ac_match_state_init(const struct ac_automaton *automaton, struct ac_match_state *state) {
    state->current_state = automaton->root;
    state->stream_pos = 0;
}

int ac_automaton_feed(struct ac_match_state *state, const u8 *data, size_t len,
                      int (*cb)(const void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
    int ret = 0;
    for (size_t i = 0; i < len; ++i) {
        u8 chr = data[i];
        const struct ac_node *node = state->current_state;
        struct ac_node *next_node = ac_node_find_next(node, chr);

        // This is the "slow path", entered only if the direct transition fails.
        // It is marked as unlikely because the performance cost of failure pointer traversal
        // (due to non-local memory access and potential cache misses) is significantly higher than a direct transition.
        if (unlikely(!next_node)) {
            while (node != node->failure) {
                node = node->failure; // backtrack to a shorter prefix
                next_node = ac_node_find_next(node, chr);
                if (next_node)
                    break;
            }
        }

        if (next_node)
            node = next_node;

        state->current_state = node;
        ++state->stream_pos;
        ret = ac_report_matches(state, cb, cb_ctx);
        if (ret != 0)
            return ret; // stop processing if callback signals stop/abort
    }
    return ret;
}
