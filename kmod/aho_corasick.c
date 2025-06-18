#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "aho_corasick.h"

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/printk.h>
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

struct ac_automaton * __must_check ac_automaton_build(struct list_head *rules_head) {
    struct ac_automaton *automaton = kmalloc(sizeof(*automaton), GFP_KERNEL);
    if (!automaton)
        return ERR_PTR(-ENOMEM);
    automaton->root = ac_node_create();
    if (!automaton->root) {
        kfree(automaton);
        return ERR_PTR(-ENOMEM);
    }

    int ret;

    struct ac_rule *rule;
    list_for_each_entry(rule, rules_head, list) {
        struct ac_node *node = automaton->root;
        const u8 *pattern = (const u8 *) rule->pattern;
        for (size_t i = 0; i < rule->len; ++i) {
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
        output->len = rule->len;
        output->priv = rule->priv;
        list_add_tail(&output->list, &node->outputs);
    }

    LIST_HEAD(queue);
    automaton->root->failure = automaton->root;
    for (int i = 0; i < 256; ++i) {
        if (automaton->root->next[i]) {
            struct ac_queue_node *qnode = kmalloc(sizeof(*qnode), GFP_KERNEL);
            if (!qnode) {
                ret = -ENOMEM;
                goto fail;
            }
            automaton->root->next[i]->failure = automaton->root;
            qnode->node = automaton->root->next[i];
            list_add_tail(&qnode->list, &queue);
        }
    }

    while (!list_empty(&queue)) {
        struct ac_queue_node *qnode = list_first_entry(&queue, struct ac_queue_node, list);
        list_del(&qnode->list);
        struct ac_node *node = qnode->node;
        for (int i = 0; i < 256; ++i) {
            struct ac_node *child = node->next[i];
            if (!child)
                continue;

            const struct ac_node *f = node->failure;
            while (f != automaton->root && !f->next[i]) {
                f = f->failure;
            }
            if (f->next[i])
                child->failure = f->next[i];
            else
                child->failure = automaton->root;

            if (!list_empty(&child->failure->outputs)) {
                struct ac_output *out;
                list_for_each_entry(out, &child->failure->outputs, list) {
                    struct ac_output *new_out = kmalloc(sizeof(*new_out), GFP_KERNEL);
                    if (!new_out) {
                        kfree(qnode);
                        ret = -ENOMEM;
                        goto fail;
                    }
                    new_out->len = out->len;
                    new_out->priv = out->priv;
                    list_add_tail(&new_out->list, &child->outputs);
                }
            }

            struct ac_queue_node *child_qnode = kmalloc(sizeof(*child_qnode), GFP_KERNEL);
            if (!child_qnode) {
                kfree(qnode);
                ret = -ENOMEM;
                goto fail;
            }
            child_qnode->node = child;
            list_add_tail(&child_qnode->list, &queue);
        }
        kfree(qnode);
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

    struct ac_queue_node *qnode = kmalloc(sizeof(*qnode), GFP_KERNEL);
    if (!qnode) {
        pr_err("Out of memory while allocating initial queue node, automaton will not be freed.\n");
        return;
    }
    qnode->node = automaton->root;
    list_add_tail(&qnode->list, &queue);

    LIST_HEAD(all_nodes); // list to collect all nodes for safe freeing
    while (!list_empty(&queue)) {
        qnode = list_first_entry(&queue, struct ac_queue_node, list);
        list_move_tail(&qnode->list, &all_nodes);

        struct ac_node *node = qnode->node;
        for (int i = 0; i < 256; i++) {
            if (node->next[i]) {
                struct ac_queue_node *child_qnode = kmalloc(sizeof(*child_qnode), GFP_KERNEL);
                if (child_qnode) {
                    child_qnode->node = node->next[i];
                    list_add_tail(&child_qnode->list, &queue);
                } else {
                    pr_err("Out of memory while traversing automaton, partial cleanup will be performed.\n");
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    struct ac_queue_node *tmp;
    // free all nodes collected in all_nodes
    list_for_each_entry_safe(qnode, tmp, &all_nodes, list) {
        ac_node_free_output(qnode->node);
        kfree(qnode->node);
        kfree(qnode);
    }

    // free any remaining wrapper nodes if cleanup was partial
    if (!list_empty(&queue)) {
        pr_warn("Freeing remaining wrapper nodes.\n");
        list_for_each_entry_safe(qnode, tmp, &queue, list) {
            kfree(qnode);
        }
    }

    kfree(automaton);
}

// int ac_automaton_match(struct ac_automaton *automaton, const struct sk_buff *skb, size_t offset, size_t len,
//                        int (*cb)(void *priv, size_t offset, void *cb_ctx), void *cb_ctx) {
// }

