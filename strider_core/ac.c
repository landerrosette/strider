#include "ac.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/types.h>
#include <linux/workqueue.h>

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
    bool has_outputs;
};

struct strider_ac {
    struct ac_node *root;
    struct work_struct destroy_work;
    struct rcu_head rcu;
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

static void ac_do_destroy(struct strider_ac *ac) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct ac_node *node = list_first_entry(&queue, struct ac_node, traversal_list);
        list_del(&node->traversal_list);

        for (size_t i = 0; i < node->num_transitions; ++i)
            list_add_tail(&node->transitions[i].next->traversal_list, &queue);
        struct ac_transition_linked *trans;
        list_for_each_entry(trans, &node->linked_transitions, list)
            list_add_tail(&trans->next->traversal_list, &queue);

        ac_node_deinit(node);
        kfree(node);
    }
    kfree(ac);
}

static void ac_destroy_work_fn(struct work_struct *work) {
    struct strider_ac *ac = container_of(work, struct strider_ac, destroy_work);
    ac_do_destroy(ac);
}

static void ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    INIT_WORK(&ac->destroy_work, ac_destroy_work_fn);
    schedule_work(&ac->destroy_work);
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
static struct ac_node *ac_failure_find_target(const struct ac_node *parent, u8 ch) {
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
            struct ac_node *failure_target = ac_failure_find_target(node, node->transitions[i].ch);
            child->failure = failure_target ? failure_target : root;
            child->has_outputs = child->has_outputs || child->failure->has_outputs;
            list_add_tail(&child->traversal_list, &queue);
        }
    }
}

struct strider_ac *ac_init(gfp_t gfp_mask) {
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

void ac_schedule_destroy(struct strider_ac *ac) {
    call_rcu(&ac->rcu, ac_destroy_rcu_cb);
}

int ac_add_pattern(struct strider_ac *ac, const u8 *pattern, size_t len, gfp_t gfp_mask) {
    struct ac_node *node = ac->root;
    for (size_t i = 0; i < len; ++i) {
        node = ac_transition_build(node, pattern[i], gfp_mask);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }
    node->has_outputs = true;
    return 0;
}

int ac_compile(struct strider_ac *ac, gfp_t gfp_mask) {
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

void ac_match_init(const struct strider_ac *ac, struct ac_match_state *state) {
    state->cursor = ac->root;
}

bool ac_match_next(struct ac_match_state *state, const u8 *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        u8 ch = data[i];
        for (const struct ac_node *node = state->cursor; ; node = node->failure) {
            // Follow transitions for the current symbol.
            // If a direct transition fails, traverse failure links
            // until a valid transition is found or the root is reached.
            const struct ac_node *next = ac_transition_find(node, ch);
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

        if (((const struct ac_node *) state->cursor)->has_outputs)
            return true;
    }
    return false;
}
