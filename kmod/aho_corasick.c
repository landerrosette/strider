#include "aho_corasick.h"

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/types.h>

// Represents a single pattern match output at a given state.
struct ac_output {
    struct list_head list;
    size_t len;
    void *priv; // caller's private context pointer, returned verbatim on match
};

struct ac_node {
    struct ac_node *next[256];
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
    INIT_LIST_HEAD(&node->outputs);
    INIT_LIST_HEAD(&node->traversal_list);
    return node;
}

static void ac_node_free_outputs(struct ac_node *node) {
    struct ac_output *out, *tmp;
    list_for_each_entry_safe(out, tmp, &node->outputs, list) {
        list_del(&out->list);
        kfree(out);
    }
}

static void ac_report_matches(struct ac_match_state *state, int (*cb)(void *priv, size_t offset, void *cb_ctx),
                              void *cb_ctx) {
    if (!cb) return;

    // Traverse the failure links chain.
    // The root's failure link points to itself, which gracefully terminates the loop.
    for (struct ac_node *node = state->current_state; node != node->failure; node = node->failure) {
        struct ac_output *out;
        list_for_each_entry(out, &node->outputs, list) {
            size_t match_offset = state->stream_pos - out->len;
            if (cb(out->priv, match_offset, cb_ctx) != 0) {
                // TODO: Implement early exit strategy.
            }
        }
    }
}

struct ac_automaton * __must_check ac_automaton_build(struct list_head *inputs_head) {
    struct ac_automaton *automaton = kmalloc(sizeof(*automaton), GFP_KERNEL);
    if (!automaton)
        return ERR_PTR(-ENOMEM);
    automaton->root = ac_node_create();
    if (!automaton->root) {
        kfree(automaton);
        return ERR_PTR(-ENOMEM);
    }

    int ret;

    struct ac_input *input;
    list_for_each_entry(input, inputs_head, list) {
        struct ac_node *node = automaton->root;
        const u8 *pattern = (const u8 *) input->pattern;
        for (size_t i = 0; i < input->len; ++i) {
            if (!node->next[pattern[i]]) {
                node->next[pattern[i]] = ac_node_create();
                if (!node->next[pattern[i]]) {
                    ret = -ENOMEM;
                    goto fail;
                }
            }
            node = node->next[pattern[i]];
        }

        struct ac_output *output = kmalloc(sizeof(*output), GFP_KERNEL);
        if (!output) {
            ret = -ENOMEM;
            goto fail;
        }
        output->len = input->len;
        output->priv = input->priv;
        list_add_tail(&output->list, &node->outputs);
    }


    LIST_HEAD(queue);

    automaton->root->failure = automaton->root;

    for (int i = 0; i < 256; ++i) {
        if (automaton->root->next[i]) {
            automaton->root->next[i]->failure = automaton->root;
            list_add_tail(&automaton->root->next[i]->traversal_list, &queue);
        }
    }

    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list); // dequeue

        for (int i = 0; i < 256; ++i) {
            struct ac_node *child = node->next[i];
            if (!child)
                continue;

            // find the failure link for the child
            const struct ac_node *f = node->failure;
            while (f != automaton->root && !f->next[i])
                f = f->failure;
            if (f->next[i])
                child->failure = f->next[i];
            else
                child->failure = automaton->root;

            list_add_tail(&child->traversal_list, &queue); // enqueue the child
        }
    }

    return automaton;

fail:
    ac_automaton_free(automaton);
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
        list_del(&node->traversal_list); // dequeue

        for (int i = 0; i < 256; i++) {
            if (node->next[i])
                list_add_tail(&node->next[i]->traversal_list, &queue);
        }

        ac_node_free_outputs(node);
        kfree(node);
    }

    kfree(automaton);
}

void ac_match_state_init(struct ac_automaton *automaton, struct ac_match_state *state) {
    state->current_state = automaton->root;
    state->stream_pos = 0;
}

void ac_automaton_feed(struct ac_match_state *state, const u8 *data, size_t len,
                       int (*cb)(void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
    for (size_t i = 0; i < len; ++i) {
        u8 b = data[i];
        struct ac_node *node = state->current_state;

        // follow failure links until a transition for the current byte is found or the root is reached
        while (node != node->failure && !node->next[b])
            node = node->failure;
        if (node->next[b])
            node = node->next[b]; // take the transition if it exists
        state->current_state = node;
        ++state->stream_pos;

        if (!list_empty(&node->outputs) || node != node->failure)
            ac_report_matches(state, cb, cb_ctx);
    }
}
