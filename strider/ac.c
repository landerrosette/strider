#include "ac.h"

#include <linux/bsearch.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/types.h>

#define STRIDER_AC_ALPHABET_SIZE 256
#define STRIDER_AC_NODE_DENSE_THRESHOLD 4

struct strider_ac_node {
    union {
        struct {
            u8 *bytes;
            struct strider_ac_node **children; // array sorted by bytes
        } sparse;

        struct {
            struct strider_ac_node **children; // array of size STRIDER_AC_ALPHABET_SIZE
        } dense;

        struct list_head build; // list of struct strider_ac_build_transition
    } transitions;

    bool is_dense;
    u8 num_children; // only valid if sparse
    struct strider_ac_node *failure;
    struct list_head outputs; // list of struct strider_ac_target
    struct strider_ac_node *output_link;
    struct list_head traversal_list;
};

struct strider_ac {
    struct strider_ac_node *root;
    struct rcu_head rcu;
};

struct strider_ac_build_transition {
    struct list_head list;
    struct strider_ac_node *next;
    u8 byte;
};

static struct strider_ac_node *strider_ac_node_create(gfp_t gfp_mask) {
    struct strider_ac_node *node = kzalloc(sizeof(*node), gfp_mask);
    if (!node)
        return NULL;
    INIT_LIST_HEAD(&node->outputs);
    INIT_LIST_HEAD(&node->traversal_list);
    INIT_LIST_HEAD(&node->transitions.build);
    return node;
}

static void strider_ac_node_destroy(struct strider_ac_node *node) {
    if (node->is_dense) {
        kfree(node->transitions.dense.children);
    } else if (node->num_children > 0) {
        kfree(node->transitions.sparse.bytes);
        kfree(node->transitions.sparse.children);
    } else {
        struct strider_ac_build_transition *tsn, *tmp;
        list_for_each_entry_safe(tsn, tmp, &node->transitions.build, list) {
            list_del(&tsn->list);
            kfree(tsn);
        }
    }
    kfree(node);
}

static void strider_ac_destroy(struct strider_ac *ac) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);

        if (node->is_dense) {
            for (int i = 0; i < STRIDER_AC_ALPHABET_SIZE; ++i) {
                struct strider_ac_node *child = node->transitions.dense.children[i];
                if (child)
                    list_add_tail(&child->traversal_list, &queue);
            }
        } else if (node->num_children > 0) {
            for (u8 i = 0; i < node->num_children; ++i) {
                struct strider_ac_node *child = node->transitions.sparse.children[i];
                list_add_tail(&child->traversal_list, &queue);
            }
        } else {
            struct strider_ac_build_transition *tsn;
            list_for_each_entry(tsn, &node->transitions.build, list)
                list_add_tail(&tsn->next->traversal_list, &queue);
        }

        strider_ac_node_destroy(node);
    }
    kfree(ac);
}

static void strider_ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    strider_ac_destroy(ac);
}

static struct strider_ac_node *strider_ac_build_next(struct strider_ac_node *node, u8 byte, gfp_t gfp_mask) {
    struct strider_ac_build_transition *tsn;

    list_for_each_entry(tsn, &node->transitions.build, list) {
        if (tsn->byte == byte)
            return tsn->next;
    }

    tsn = kmalloc(sizeof(*tsn), gfp_mask);
    if (!tsn)
        return ERR_PTR(-ENOMEM);
    tsn->next = strider_ac_node_create(gfp_mask);
    if (!tsn->next) {
        kfree(tsn);
        return ERR_PTR(-ENOMEM);
    }
    tsn->byte = byte;
    list_add_tail(&tsn->list, &node->transitions.build);
    return tsn->next;
}

static int strider_ac_build_transition_compare(void *priv, const struct list_head *a, const struct list_head *b) {
    const struct strider_ac_build_transition *ta = list_entry(a, struct strider_ac_build_transition, list);
    const struct strider_ac_build_transition *tb = list_entry(b, struct strider_ac_build_transition, list);
    return ta->byte - tb->byte;
}

static int strider_ac_finalize_transitions(struct strider_ac_node *node, gfp_t gfp_mask) {
    int count = 0;
    struct strider_ac_build_transition *tsn;
    list_for_each_entry(tsn, &node->transitions.build, list)
        ++count;

    if (count >= STRIDER_AC_NODE_DENSE_THRESHOLD) {
        struct strider_ac_node **children = kcalloc(STRIDER_AC_ALPHABET_SIZE, sizeof(*children), gfp_mask);
        if (!children)
            return -ENOMEM;
        list_for_each_entry(tsn, &node->transitions.build, list)
            children[tsn->byte] = tsn->next;
        node->transitions.dense.children = children;
        node->is_dense = true;
    } else if (count > 0) {
        struct strider_ac_node **children = kmalloc_array(count, sizeof(*children), gfp_mask);
        if (!children)
            return -ENOMEM;
        u8 *bytes = kmalloc_array(count, sizeof(*bytes), gfp_mask);
        if (!bytes) {
            kfree(children);
            return -ENOMEM;
        }

        list_sort(NULL, &node->transitions.build, strider_ac_build_transition_compare);
        u8 i = 0;
        struct strider_ac_build_transition *tmp;
        list_for_each_entry_safe(tsn, tmp, &node->transitions.build, list) {
            children[i] = tsn->next;
            bytes[i] = tsn->byte;
            ++i;
            list_del(&tsn->list);
            kfree(tsn);
        }

        node->transitions.sparse.children = children;
        node->transitions.sparse.bytes = bytes;
        node->num_children = i;
    }

    return 0;
}

static int strider_ac_byte_compare(const void *a, const void *b) {
    return *(u8 *) a - *(u8 *) b;
}

// called on a node with finalized transitions
static struct strider_ac_node *strider_ac_find_next(const struct strider_ac_node *node, u8 byte) {
    if (node->is_dense) {
        return node->transitions.dense.children[byte];
    } else {
        const u8 *pb = bsearch(&byte, node->transitions.sparse.bytes, node->num_children, sizeof(byte),
                               strider_ac_byte_compare);
        if (!pb)
            return NULL;
        return node->transitions.sparse.children[pb - node->transitions.sparse.bytes];
    }
}

static struct strider_ac_node *strider_ac_find_failure(const struct strider_ac_node *parent, u8 byte) {
    const struct strider_ac_node *node;
    for (node = parent->failure; node != node->failure; node = node->failure) {
        struct strider_ac_node *next = strider_ac_find_next(node, byte);
        if (next)
            return next;
    }
    // node is now root
    return strider_ac_find_next(node, byte);
}

static void strider_ac_finalize(struct strider_ac_node *root) {
    root->failure = root;
    LIST_HEAD(queue);

    // point root's children's failure links to root
    if (root->is_dense) {
        for (int i = 0; i < STRIDER_AC_ALPHABET_SIZE; ++i) {
            struct strider_ac_node *child = root->transitions.dense.children[i];
            if (child) {
                child->failure = root;
                list_add_tail(&child->traversal_list, &queue);
            }
        }
    } else {
        for (u8 i = 0; i < root->num_children; ++i) {
            struct strider_ac_node *child = root->transitions.sparse.children[i];
            child->failure = root;
            list_add_tail(&child->traversal_list, &queue);
        }
    }

    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);
        if (node->is_dense) {
            for (int i = 0; i < STRIDER_AC_ALPHABET_SIZE; ++i) {
                struct strider_ac_node *child = node->transitions.dense.children[i];
                if (child) {
                    struct strider_ac_node *failure_node = strider_ac_find_failure(node, i);
                    child->failure = failure_node ? failure_node : root;
                    child->output_link = list_empty(&child->failure->outputs)
                                             ? child->failure->output_link
                                             : child->failure;
                    list_add_tail(&child->traversal_list, &queue);
                }
            }
        } else {
            for (u8 i = 0; i < node->num_children; ++i) {
                struct strider_ac_node *child = node->transitions.sparse.children[i];
                struct strider_ac_node *failure_node = strider_ac_find_failure(node, node->transitions.sparse.bytes[i]);
                child->failure = failure_node ? failure_node : root;
                child->output_link = list_empty(&child->failure->outputs)
                                         ? child->failure->output_link
                                         : child->failure;
                list_add_tail(&child->traversal_list, &queue);
            }
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

int strider_ac_add_target(struct strider_ac *ac, struct strider_ac_target *target, gfp_t gfp_mask) {
    struct strider_ac_node *node = ac->root;
    for (size_t i = 0; i < target->pattern_len; ++i) {
        node = strider_ac_build_next(node, target->pattern[i], gfp_mask);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }
    list_add(&target->list, &node->outputs);
    return 0;
}

int strider_ac_compile(struct strider_ac *ac, gfp_t gfp_mask) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->traversal_list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, traversal_list);
        list_del(&node->traversal_list);
        int ret = strider_ac_finalize_transitions(node, gfp_mask);
        if (ret < 0) {
            struct strider_ac_node *tmp;
            // clear the in-flight traversal queue
            list_for_each_entry_safe(node, tmp, &queue, traversal_list)
                list_del(&node->traversal_list);
            return ret;
        }
        if (node->is_dense) {
            for (int i = 0; i < STRIDER_AC_ALPHABET_SIZE; ++i) {
                struct strider_ac_node *child = node->transitions.dense.children[i];
                if (child)
                    list_add_tail(&child->traversal_list, &queue);
            }
        } else {
            for (u8 i = 0; i < node->num_children; ++i) {
                struct strider_ac_node *child = node->transitions.sparse.children[i];
                list_add_tail(&child->traversal_list, &queue);
            }
        }
    }
    strider_ac_finalize(ac->root);
    return 0;
}

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state) {
    state->cursor = ac->root;
}

int strider_ac_match(struct strider_ac_match_state *state, const u8 *data, size_t len,
                     int (*cb)(const struct strider_ac_target *target, size_t pos, void *ctx), void *cb_ctx) {
    const struct strider_ac_node *cursor = state->cursor;
    int ret = 0;
    for (size_t i = 0; i < len; ++i) {
        for (const struct strider_ac_node *node = cursor; ; node = node->failure) {
            const struct strider_ac_node *next = strider_ac_find_next(node, data[i]);
            if (next) {
                cursor = next;
                break;
            }
            if (node->failure == node) {
                // reached root
                cursor = node;
                break;
            }
        }

        for (const struct strider_ac_node *node = cursor; node; node = node->output_link) {
            if (!list_empty(&node->outputs)) {
                const struct strider_ac_target *target;
                list_for_each_entry(target, &node->outputs, list) {
                    ret = cb(target, i, cb_ctx);
                    if (ret != 0)
                        goto out;
                }
            }
        }
    }
out:
    state->cursor = cursor;
    return ret;
}
