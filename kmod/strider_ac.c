#include "strider_ac.h"

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/rcupdate.h>

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

// Represents a single pattern match output at a given state.
struct ac_output {
    struct list_head list;
    size_t len;
};

struct ac_node {
    struct ac_transition *transitions;
    size_t num_transitions;

    struct list_head build_transitions;

    struct ac_node *failure;
    struct list_head outputs;        // list of ac_output
    struct list_head traversal_list; // for build/free traversals
};

struct strider_ac_automaton {
    struct ac_node *root;
    struct rcu_head rcu;
};

static struct ac_node *ac_node_create(void) {
    struct ac_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return NULL;
    INIT_LIST_HEAD(&node->build_transitions);
    INIT_LIST_HEAD(&node->outputs);
    INIT_LIST_HEAD(&node->traversal_list);
    return node;
}

// free all resources associated with a node
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

// get or create a transition for a character during build
static struct ac_node *ac_trie_get_or_create_next_node(struct ac_node *node, u8 chr) {
    struct ac_build_transition *bt;

    list_for_each_entry(bt, &node->build_transitions, list) {
        if (bt->chr == chr)
            return bt->next;
    }

    bt = kmalloc(sizeof(*bt), GFP_KERNEL);
    if (!bt)
        return ERR_PTR(-ENOMEM);
    bt->next = ac_node_create();
    if (!bt->next) {
        kfree(bt);
        return ERR_PTR(-ENOMEM);
    }
    bt->chr = chr;
    list_add_tail(&bt->list, &node->build_transitions);
    return bt->next;
}

static int ac_trie_add_pattern(struct ac_node *root, const char *pattern, size_t len) {
    struct ac_node *node = root;

    for (size_t i = 0; i < len; ++i) {
        node = ac_trie_get_or_create_next_node(node, ((const u8 *)pattern)[i]);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }

    struct ac_output *output = kmalloc(sizeof(*output), GFP_KERNEL);
    if (!output)
        return -ENOMEM;
    output->len = len;
    list_add_tail(&output->list, &node->outputs);

    return 0;
}

static int ac_transition_compare(const void *a, const void *b) {
    const struct ac_transition *ta = a;
    const struct ac_transition *tb = b;
    return ta->chr - tb->chr;
}

// convert the temporary linked-list of transitions into a sorted array
static int ac_node_finalize_transitions(struct ac_node *node) {
    size_t count = 0;
    struct ac_build_transition *bt;
    list_for_each_entry(bt, &node->build_transitions, list)
        ++count;

    if (count > 0) {
        node->transitions = kcalloc(count, sizeof(*node->transitions), GFP_KERNEL);
        if (!node->transitions)
            return -ENOMEM;
        struct ac_build_transition *tmp;
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
        sort(node->transitions, count, sizeof(*node->transitions), ac_transition_compare, NULL);
    }

    return 0;
}

// finalize the trie by compacting transitions
static int ac_trie_finalize(struct ac_node *root) {
    LIST_HEAD(queue);
    int ret = 0;
    list_add_tail(&root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list);
        ret = ac_node_finalize_transitions(node);
        if (ret < 0)
            goto fail;
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct ac_node *child = node->transitions[i].next;
            list_add_tail(&child->traversal_list, &queue);
        }
    }

out:
    WARN_ON_ONCE(!list_empty(&queue));
    return ret;

fail:
    struct ac_node *node, *tmp;
    // clear the in-flight traversal queue
    list_for_each_entry_safe(node, tmp, &queue, traversal_list)
        list_del(&node->traversal_list);
    goto out;
}

// find the next transition for a character, called on a node with compacted transitions
static struct ac_node *ac_node_find_transition(const struct ac_node *node, u8 chr) {
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
static struct ac_node *ac_failure_find_target(const struct ac_node *parent, u8 chr) {
    const struct ac_node *node;
    for (node = parent->failure; node != node->failure; node = node->failure) {
        struct ac_node *target = ac_node_find_transition(node, chr);
        if (target)
            return target;
    }
    // node is now root
    return ac_node_find_transition(node, chr);
}

static void ac_failure_build_links(struct ac_node *root) {
    root->failure = root;
    LIST_HEAD(queue);
    // point root's children's failure links to root
    for (size_t i = 0; i < root->num_transitions; ++i) {
        struct ac_node *child = root->transitions[i].next;
        child->failure = root;
        list_add_tail(&child->traversal_list, &queue); // enqueue the child for BFS traversal
    }
    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list); // dequeue
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct ac_node *child = node->transitions[i].next;
            struct ac_node *failure_target =
                    ac_failure_find_target(node, node->transitions[i].chr);
            child->failure = failure_target ? failure_target : root;
            list_add_tail(&child->traversal_list, &queue); // enqueue the child
        }
    }
}

struct strider_ac_automaton * __must_check strider_ac_automaton_build(const char * const *patterns, size_t num_patterns) {
    struct strider_ac_automaton *automaton = kzalloc(sizeof(*automaton), GFP_KERNEL);
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

    for (size_t i = 0; i < num_patterns; ++i) {
        const char *pattern = patterns[i];
        size_t len = strlen(pattern);
        ret = ac_trie_add_pattern(automaton->root, pattern, len);
        if (ret < 0)
            goto fail_automaton_free;
    }

    ret = ac_trie_finalize(automaton->root);
    if (ret < 0)
        goto fail_automaton_free;

    ac_failure_build_links(automaton->root);

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

        ac_node_deinit(node);
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
                              int (*cb)(void *cb_ctx), void *cb_ctx) {
    if (unlikely(!state->automaton))
        return 0;
    const struct ac_node *root = state->automaton->root;
    for (size_t i = 0; i < len; ++i) {
        // Follow transitions for the current character.
        // If a direct transition fails, traverse failure links
        // until a valid transition is found or the root is reached.
        u8 chr = data[i];
        const struct ac_node *curr_node = state->cursor;
        while (true) {
            const struct ac_node *next = ac_node_find_transition(curr_node, chr);
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
        for (const struct ac_node *out_node = state->cursor;; out_node = out_node->failure) {
            if (!list_empty(&out_node->outputs)) {
                const struct ac_output *out;
                list_for_each_entry(out, &out_node->outputs, list) {
                    int ret = cb(cb_ctx);
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
