#include "aho_corasick.h"

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/types.h>

// Represents a pattern that ends at a specific node in the Trie.
struct ac_output {
    struct list_head list;
    size_t len;
    void *priv; // pointer back to the original rule context
};

struct ac_node {
    struct ac_node *next[256];
    struct ac_node *failure;
    struct list_head outputs; // list of ac_output
};

struct ac_queue_node {
    struct list_head list;
    struct ac_node *node;
};

struct ac_automaton {
    struct ac_node *root;
};

static struct ac_node *ac_node_create(void) {
    struct ac_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return NULL;
    INIT_LIST_HEAD(&node->outputs);
    return node;
}

static inline void ac_node_free_output(struct ac_node *node) {
    struct ac_output *out, *tmp;
    list_for_each_entry_safe(out, tmp, &node->outputs, list) {
        list_del(&out->list);
        kfree(out);
    }
}

struct ac_automaton * __must_check ac_automaton_build(struct list_head *head) {
}

void ac_automaton_free(struct ac_automaton *automaton) {
}

int ac_automaton_match(struct ac_automaton *automaton, const struct sk_buff *skb, size_t offset, size_t len,
                       int (*cb)(void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
}

