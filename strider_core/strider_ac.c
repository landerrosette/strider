#include "strider_ac.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>
// #include <linux/string.h>
#include <linux/types.h>

// Represents a finalized, read-only transition.
struct ac_transition {
    struct ac_node *next;
    u8 ch;
};

// Represents a temporary transition used during trie construction.
struct ac_transition_linked {
    struct list_head list;
    struct ac_node *next;
    u8 ch;
};

struct ac_node {
    struct list_head linked_transitions;
    struct list_head traversal_list;
    struct ac_node *failure;
    struct ac_transition *transitions;
    size_t num_transitions;
    bool is_output;
};

struct strider_ac {
    struct ac_node *root;
};

static struct ac_node *ac_node_create(gfp_t gfp_mask) {
    struct ac_node *node = kzalloc(sizeof(*node), gfp_mask);
    if (!node) return NULL;
    INIT_LIST_HEAD(&node->linked_transitions);
    INIT_LIST_HEAD(&node->traversal_list);
    return node;
}

static void ac_node_deinit(struct ac_node *node) {
    kfree(node->transitions);

    struct ac_transition_linked *trans, *tmp;
    list_for_each_entry_safe(trans, tmp, &node->linked_transitions, list) {
        list_del(&trans->list);
        kfree(trans);
    }
}

static struct ac_node *ac_transition_build(struct ac_node *node, u8 ch, gfp_t gfp_mask) {
    struct ac_transition_linked *trans;

    list_for_each_entry(trans, &node->linked_transitions, list) {
        if (trans->ch == ch)
            return trans->next;
    }

    trans = kmalloc(sizeof(*trans), gfp_mask);
    if (!trans)
        return ERR_PTR(-ENOMEM);
    trans->next = ac_node_create(gfp_mask);
    if (!trans->next) {
        kfree(trans);
        return ERR_PTR(-ENOMEM);
    }
    trans->ch = ch;
    list_add_tail(&trans->list, &node->linked_transitions);
    return trans->next;
}

static int ac_transition_compare(const void *a, const void *b) {
    const struct ac_transition *ta = a;
    const struct ac_transition *tb = b;
    return ta->ch - tb->ch;
}

// convert the temporary linked-list of transitions into a sorted array
static int ac_transitions_finalize(struct ac_node *node, gfp_t gfp_mask) {
    size_t count = 0;
    struct ac_transition_linked *trans;
    list_for_each_entry(trans, &node->linked_transitions, list)
        ++count;

    if (count > 0) {
        node->transitions = kmalloc_array(count, sizeof(*node->transitions), gfp_mask);
        if (!node->transitions)
            return -ENOMEM;
        struct ac_transition_linked *tmp;
        size_t i = 0;
        // copy transitions from the temporary list to the final array
        list_for_each_entry_safe(trans, tmp, &node->linked_transitions, list) {
            node->transitions[i].next = trans->next;
            node->transitions[i].ch = trans->ch;
            ++i;
            list_del(&trans->list);
            kfree(trans);
        }
        node->num_transitions = count;
        sort(node->transitions, count, sizeof(*node->transitions), ac_transition_compare, NULL);
    }

    return 0;
}

// called on a node with finalized transitions
static struct ac_node *ac_transition_find(const struct ac_node *node, u8 ch) {
    size_t left = 0, right = node->num_transitions;
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        if (node->transitions[mid].ch < ch)
            left = mid + 1;
        else
            right = mid;
    }
    if (left < node->num_transitions && node->transitions[left].ch == ch)
        return node->transitions[left].next;
    return NULL;
}

// find the failure link target for a node, starting from its parent
static struct ac_node *ac_failure_build(const struct ac_node *parent, u8 ch) {
    const struct ac_node *node;
    for (node = parent->failure; node != node->failure; node = node->failure) {
        struct ac_node *target = ac_transition_find(node, ch);
        if (target)
            return target;
    }
    // node is now root
    return ac_transition_find(node, ch);
}

static void ac_failures_build(struct ac_node *root) {
    root->failure = root;
    LIST_HEAD(queue);
    // point root's children's failure links to root
    for (size_t i = 0; i < root->num_transitions; ++i) {
        struct ac_node *child = root->transitions[i].next;
        child->failure = root;
        list_add_tail(&child->traversal_list, &queue);
    }
    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list);
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct ac_node *child = node->transitions[i].next;
            struct ac_node *failure_target = ac_failure_build(node, node->transitions[i].ch);
            child->failure = failure_target ? failure_target : root;
            list_add_tail(&child->traversal_list, &queue);
        }
    }
}

struct strider_ac *strider_ac_init(gfp_t gfp_mask) {
    struct strider_ac *ac = kmalloc(sizeof(*ac), gfp_mask);
    if (!ac)
        return ERR_PTR(-ENOMEM);
    ac->root = ac_node_create(gfp_mask);
    if (!ac->root) {
        kfree(ac);
        return ERR_PTR(-ENOMEM);
    }
    return ac;
}

int strider_ac_add_pattern(struct strider_ac *ac, const u8 *pattern, size_t len, gfp_t gfp_mask) {
    struct ac_node *node = ac->root;
    for (size_t i = 0; i < len; ++i) {
        node = ac_transition_build(node, pattern[i], gfp_mask);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }
    node->is_output = true;
    return 0;
}

int strider_ac_compile(struct strider_ac *ac, gfp_t gfp_mask) {
    LIST_HEAD(queue);
    int ret = 0;

    list_add_tail(&ac->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list);
        ret = ac_transitions_finalize(node, gfp_mask);
        if (ret < 0)
            goto fail;
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct ac_node *child = node->transitions[i].next;
            list_add_tail(&child->traversal_list, &queue);
        }
    }

    ac_failures_build(ac->root);

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

// static void __cold ac_automaton_do_destroy(struct strider_ac_automaton *automaton) {
//     if (!automaton->root) {
//         kfree(automaton);
//         return;
//     }

//     LIST_HEAD(queue);
//     list_add_tail(&automaton->root->traversal_list, &queue);
//     while (!list_empty(&queue)) {
//         struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
//         list_del(&node->traversal_list); // dequeue the current node

//         // enqueue all children for the next cleanup iteration
//         if (node->transitions) {
//             for (size_t i = 0; i < node->num_transitions; ++i)
//                 list_add_tail(&node->transitions[i].next->traversal_list, &queue);
//         } else {
//             struct ac_transition_linked *bt;
//             list_for_each_entry(bt, &node->linked_transitions, list)
//                 list_add_tail(&bt->next->traversal_list, &queue);
//         }

//         ac_node_deinit(node);
//         kfree(node);
//     }

//     kfree(automaton);
// }

// struct strider_ac_automaton * __cold __must_check strider_ac_automaton_compile(
//     const char *const *patterns, size_t num_patterns) {
//     struct strider_ac_automaton *automaton = kzalloc(sizeof(*automaton), GFP_KERNEL);
//     int ret = 0;
//     if (!automaton) {
//         ret = -ENOMEM;
//         goto fail;
//     }
//     automaton->root = ac_node_create();
//     if (!automaton->root) {
//         kfree(automaton);
//         ret = -ENOMEM;
//         goto fail;
//     }
//     automaton->root->failure = automaton->root;

//     for (size_t i = 0; i < num_patterns; ++i) {
//         const char *pattern = patterns[i];
//         size_t len = strlen(pattern);
//         ret = ac_trie_add_pattern(automaton->root, pattern, len);
//         if (ret < 0)
//             goto fail_automaton_destroy;
//     }

//     ret = ac_trie_finalize(automaton->root);
//     if (ret < 0)
//         goto fail_automaton_destroy;

//     ac_failures_build(automaton->root);

//     return automaton;

// fail_automaton_destroy:
//     strider_ac_automaton_destroy(automaton);
// fail:
//     return ERR_PTR(ret);
// }

// void __cold strider_ac_automaton_destroy(struct strider_ac_automaton *automaton) {
//     if (automaton)
//         ac_automaton_do_destroy(automaton);
// }

// void __cold strider_ac_automaton_destroy_rcu(struct strider_ac_automaton *automaton) {
//     if (automaton)
//         call_rcu(&automaton->rcu, ac_automaton_destroy_rcu_cb);
// }

// void strider_ac_match_state_init(struct strider_ac_match_state *state, const struct strider_ac_automaton *automaton) {
//     state->cursor = automaton->root;
//     state->automaton = automaton;
//     state->stream_pos = 0;
// }

// int strider_ac_automaton_scan(struct strider_ac_match_state *state, const u8 *data, size_t len,
//                               int (*cb)(void *cb_ctx), void *cb_ctx) {
//     if (unlikely(!state->automaton))
//         return 0;
//     const struct ac_node *root = state->automaton->root;
//     for (size_t i = 0; i < len; ++i) {
//         // Follow transitions for the current character.
//         // If a direct transition fails, traverse failure links
//         // until a valid transition is found or the root is reached.
//         u8 chr = data[i];
//         const struct ac_node *curr_node = state->cursor;
//         while (true) {
//             const struct ac_node *next = ac_transition_find(curr_node, chr);
//             if (next) {
//                 state->cursor = next;
//                 break;
//             }
//             if (curr_node == root) {
//                 state->cursor = root;
//                 break;
//             }
//             curr_node = curr_node->failure;
//         }

//         // Inspect each node in the failure chain starting from the final state, to report all matches.
//         // This is done to ensure that all patterns that end at the current position are reported,
//         // including shorter patterns that are suffixes of longer ones.
//         for (const struct ac_node *out_node = state->cursor;; out_node = out_node->failure) {
//             if (!list_empty(&out_node->outputs)) {
//                 const struct ac_output *out;
//                 list_for_each_entry(out, &out_node->outputs, list) {
//                     int ret = cb(cb_ctx);
//                     if (ret != 0) {
//                         // callback requested to stop
//                         state->stream_pos += i + 1;
//                         return ret;
//                     }
//                 }
//             }
//             if (out_node == root)
//                 break;
//         }
//     }

//     state->stream_pos += len;
//     return 0;
// }

// static int __cold ac_trie_add_pattern(struct ac_node *root, const char *pattern, size_t len) {
//     struct ac_node *node = root;

//     for (size_t i = 0; i < len; ++i) {
//         node = ac_transition_build(node, ((const u8 *) pattern)[i]);
//         if (IS_ERR(node))
//             return PTR_ERR(node);
//     }

//     struct ac_output *output = kmalloc(sizeof(*output), GFP_KERNEL);
//     if (!output)
//         return -ENOMEM;
//     output->len = len;
//     list_add_tail(&output->list, &node->outputs);

//     return 0;
// }

// // finalize the trie by compacting transitions
// static int ac_trie_finalize(struct ac_node *root) {
//     LIST_HEAD(queue);
//     int ret = 0;
//     list_add_tail(&root->traversal_list, &queue);
//     while (!list_empty(&queue)) {
//         struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
//         list_del(&node->traversal_list);
//         ret = ac_transitions_finalize(node);
//         if (ret < 0)
//             goto fail;
//         for (size_t i = 0; i < node->num_transitions; ++i) {
//             struct ac_node *child = node->transitions[i].next;
//             list_add_tail(&child->traversal_list, &queue);
//         }
//     }

// out:
//     WARN_ON_ONCE(!list_empty(&queue));
//     return ret;

// fail:
//     struct ac_node *node, *tmp;
//     // clear the in-flight traversal queue
//     list_for_each_entry_safe(node, tmp, &queue, traversal_list)
//         list_del(&node->traversal_list);
//     goto out;
// }
