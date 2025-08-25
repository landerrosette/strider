#include "ac.h"

#include <linux/bug.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/types.h>
#include <linux/workqueue.h>

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
    struct list_head linked_transitions;
    struct list_head traversal_list;
    struct strider_ac_node *failure;
    struct strider_ac_transition *transitions;
    size_t num_transitions;
    bool has_outputs;
};

struct strider_ac {
    struct strider_ac_node *root;
    struct work_struct destroy_work;
    struct rcu_head rcu;
};

static struct strider_ac_node *strider_ac_node_create(gfp_t gfp_mask) {
    struct strider_ac_node *node = kzalloc(sizeof(*node), gfp_mask);
    if (!node) return NULL;
    INIT_LIST_HEAD(&node->linked_transitions);
    INIT_LIST_HEAD(&node->traversal_list);
    return node;
}

static void strider_ac_node_deinit(struct strider_ac_node *node) {
    kfree(node->transitions);

    struct strider_ac_transition_linked *trans, *tmp;
    list_for_each_entry_safe(trans, tmp, &node->linked_transitions, list) {
        list_del(&trans->list);
        kfree(trans);
    }
}

static void strider_ac_do_destroy(struct strider_ac *ac) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);

        for (size_t i = 0; i < node->num_transitions; ++i)
            list_add_tail(&node->transitions[i].next->traversal_list, &queue);
        struct strider_ac_transition_linked *trans;
        list_for_each_entry(trans, &node->linked_transitions, list)
            list_add_tail(&trans->next->traversal_list, &queue);

        strider_ac_node_deinit(node);
        kfree(node);
    }
    kfree(ac);
}

static void strider_ac_destroy_work_fn(struct work_struct *work) {
    struct strider_ac *ac = container_of(work, struct strider_ac, destroy_work);
    strider_ac_do_destroy(ac);
}

static void strider_ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    INIT_WORK(&ac->destroy_work, strider_ac_destroy_work_fn);
    schedule_work(&ac->destroy_work);
}

static struct strider_ac_node *strider_ac_transition_build(struct strider_ac_node *node, u8 ch, gfp_t gfp_mask) {
    struct strider_ac_transition_linked *trans;

    list_for_each_entry(trans, &node->linked_transitions, list) {
        if (trans->ch == ch)
            return trans->next;
    }

    trans = kmalloc(sizeof(*trans), gfp_mask);
    if (!trans)
        return ERR_PTR(-ENOMEM);
    trans->next = strider_ac_node_create(gfp_mask);
    if (!trans->next) {
        kfree(trans);
        return ERR_PTR(-ENOMEM);
    }
    trans->ch = ch;
    list_add_tail(&trans->list, &node->linked_transitions);
    return trans->next;
}

static int strider_ac_transition_compare(const void *a, const void *b) {
    const struct strider_ac_transition *ta = a;
    const struct strider_ac_transition *tb = b;
    return ta->ch - tb->ch;
}

// convert the temporary linked-list of transitions into a sorted array
static int strider_ac_transitions_finalize(struct strider_ac_node *node, gfp_t gfp_mask) {
    size_t count = 0;
    struct strider_ac_transition_linked *trans;
    list_for_each_entry(trans, &node->linked_transitions, list)
        ++count;

    if (count > 0) {
        node->transitions = kmalloc_array(count, sizeof(*node->transitions), gfp_mask);
        if (!node->transitions)
            return -ENOMEM;
        struct strider_ac_transition_linked *tmp;
        size_t i = 0;
        // copy transitions from the temporary list to the final array
        list_for_each_entry_safe(trans, tmp, &node->linked_transitions, list) {
            node->transitions[i].next = trans->next;
            node->transitions[i].ch = trans->ch;
            ++i;
            list_del(&trans->list);
            kfree(trans);
        }
        BUG_ON(i != count);
        node->num_transitions = count;
        sort(node->transitions, count, sizeof(*node->transitions), strider_ac_transition_compare, NULL);
    }

    return 0;
}

// called on a node with finalized transitions
static struct strider_ac_node *strider_ac_transition_find(const struct strider_ac_node *node, u8 ch) {
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
static struct strider_ac_node *strider_ac_failure_find_target(const struct strider_ac_node *parent, u8 ch) {
    const struct strider_ac_node *node;
    for (node = parent->failure; node != node->failure; node = node->failure) {
        struct strider_ac_node *target = strider_ac_transition_find(node, ch);
        if (target)
            return target;
    }
    // node is now root
    return strider_ac_transition_find(node, ch);
}

static void strider_ac_failures_build(struct strider_ac_node *root) {
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
            struct strider_ac_node *failure_target = strider_ac_failure_find_target(node, node->transitions[i].ch);
            child->failure = failure_target ? failure_target : root;
            child->has_outputs = child->has_outputs || child->failure->has_outputs;
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

int strider_ac_add_pattern(struct strider_ac *ac, const u8 *pattern, size_t len, gfp_t gfp_mask) {
    struct strider_ac_node *node = ac->root;
    for (size_t i = 0; i < len; ++i) {
        node = strider_ac_transition_build(node, pattern[i], gfp_mask);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }
    node->has_outputs = true;
    return 0;
}

int strider_ac_compile(struct strider_ac *ac, gfp_t gfp_mask) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->traversal_list, &queue);
    int ret = 0;
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);
        ret = strider_ac_transitions_finalize(node, gfp_mask);
        if (ret < 0) {
            struct strider_ac_node *tmp;
            // clear the in-flight traversal queue
            list_for_each_entry_safe(node, tmp, &queue, traversal_list)
                list_del(&node->traversal_list);
            goto out;
        }
        for (size_t i = 0; i < node->num_transitions; ++i) {
            struct strider_ac_node *child = node->transitions[i].next;
            list_add_tail(&child->traversal_list, &queue);
        }
    }
    strider_ac_failures_build(ac->root);
out:
    BUG_ON(!list_empty(&queue));
    return ret;
}

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state) {
    state->cursor = ac->root;
}

bool strider_ac_match_next(struct strider_ac_match_state *state, const u8 *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        u8 ch = data[i];
        for (const struct strider_ac_node *node = state->cursor; ; node = node->failure) {
            // Follow transitions for the current symbol.
            // If a direct transition fails, traverse failure links
            // until a valid transition is found or the root is reached.
            const struct strider_ac_node *next = strider_ac_transition_find(node, ch);
            if (next) {
                state->cursor = next;
                break;
            }
            if (node->failure == node) {
                // reached root
                state->cursor = node;
                break;
            }
        }

        if (((const struct strider_ac_node *) state->cursor)->has_outputs)
            return true;
    }
    return false;
}
