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
    const void *priv; // caller's private context pointer, returned verbatim on match
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

static int ac_report_matches(const struct ac_match_state *state,
                             int (*cb)(const void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
    int ret = 0;
    if (!cb) return ret;

    // Traverse the failure links chain.
    // The root's failure link points to itself, which gracefully terminates the loop.
    for (const struct ac_node *node = state->current_state; node != node->failure; node = node->failure) {
        const struct ac_output *out;
        list_for_each_entry(out, &node->outputs, list) {
            size_t match_offset = state->stream_pos - out->len;
            ret = cb(out->priv, match_offset, cb_ctx);
            if (ret != 0)
                return ret; // immediately exit and propagate the signal
        }
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

    struct ac_input *input;
    list_for_each_entry(input, inputs_head, list) {
        struct ac_node *node = automaton->root;
        const u8 *pattern = (const u8 *) input->pattern;
        for (size_t i = 0; i < input->len; ++i) {
            if (!node->next[pattern[i]]) {
                node->next[pattern[i]] = ac_node_create();
                if (!node->next[pattern[i]]) {
                    ret = -ENOMEM;
                    goto fail_automaton_free;
                }
            }
            node = node->next[pattern[i]];
        }

        struct ac_output *output = kmalloc(sizeof(*output), GFP_KERNEL);
        if (!output) {
            ret = -ENOMEM;
            goto fail_automaton_free;
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

void ac_match_state_init(const struct ac_automaton *automaton, struct ac_match_state *state) {
    state->current_state = automaton->root;
    state->stream_pos = 0;
}

int ac_automaton_feed(struct ac_match_state *state, const u8 *data, size_t len,
                      int (*cb)(const void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
    int ret = 0;
    for (size_t i = 0; i < len; ++i) {
        u8 b = data[i];
        const struct ac_node *node = state->current_state;

        // follow failure links until a transition for the current byte is found or the root is reached
        while (node != node->failure && !node->next[b])
            node = node->failure;
        if (node->next[b])
            node = node->next[b]; // take the transition if it exists
        state->current_state = node;
        ++state->stream_pos;

        if (!list_empty(&node->outputs) || node != node->failure) {
            ret = ac_report_matches(state, cb, cb_ctx);
            if (ret != 0)
                return ret; // stop processing if callback signals stop/abort
        }
    }
    return ret;
}
