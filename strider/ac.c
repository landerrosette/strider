#include "ac.h"

#include <linux/bsearch.h>
#include <linux/compiler.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/types.h>

#define STRIDER_AC_ALPHABET_SIZE 256
#define STRIDER_AC_TRANSITIONS_SPARSE_LIMIT 16

struct strider_ac_node {
    union {
        struct {
            struct strider_ac_node **children; // array of size STRIDER_AC_ALPHABET_SIZE
        } dense;

        struct {
            u8 *bytes;
            struct strider_ac_node **children; // array sorted by bytes
        } sparse;

        struct list_head linked;
    } transitions;

    enum {
        STRIDER_AC_TRANSITIONS_LINKED,
        STRIDER_AC_TRANSITIONS_DENSE,
        STRIDER_AC_TRANSITIONS_SPARSE,
    } transitions_type;

    u16 num_children;
    struct strider_ac_node *failure;
    struct list_head outputs; // list of struct strider_ac_target
    struct strider_ac_node *output_link;
    struct list_head list; // for traversal
};

struct strider_ac {
    struct strider_ac_node *root;
    struct rcu_head rcu;
};

struct strider_ac_linked_transition {
    struct list_head list;
    struct strider_ac_node *next;
    u8 byte;
};

static struct kmem_cache *strider_ac_node_cache;
static struct kmem_cache *strider_ac_linked_transition_cache;

int strider_ac_caches_create(void) {
    strider_ac_node_cache = KMEM_CACHE(strider_ac_node, SLAB_HWCACHE_ALIGN);
    if (!strider_ac_node_cache)
        return -ENOMEM;
    strider_ac_linked_transition_cache = KMEM_CACHE(strider_ac_linked_transition, SLAB_HWCACHE_ALIGN);
    if (!strider_ac_linked_transition_cache) {
        kmem_cache_destroy(strider_ac_node_cache);
        return -ENOMEM;
    }
    return 0;
}

void strider_ac_caches_destroy(void) {
    kmem_cache_destroy(strider_ac_linked_transition_cache);
    kmem_cache_destroy(strider_ac_node_cache);
}

static struct strider_ac_node *strider_ac_node_create(gfp_t gfp_mask) {
    struct strider_ac_node *node = kmem_cache_zalloc(strider_ac_node_cache, gfp_mask);
    if (!node)
        return NULL;
    INIT_LIST_HEAD(&node->outputs);
    INIT_LIST_HEAD(&node->transitions.linked);
    return node;
}

static void strider_ac_node_destroy(struct strider_ac_node *node) {
    switch (node->transitions_type) {
        case STRIDER_AC_TRANSITIONS_LINKED: {
            struct strider_ac_linked_transition *tsn, *tmp;
            list_for_each_entry_safe(tsn, tmp, &node->transitions.linked, list) {
                list_del(&tsn->list);
                kmem_cache_free(strider_ac_linked_transition_cache, tsn);
            }
            break;
        }
        case STRIDER_AC_TRANSITIONS_DENSE:
            kfree(node->transitions.dense.children);
            break;
        case STRIDER_AC_TRANSITIONS_SPARSE:
            kfree(node->transitions.sparse.bytes);
            kfree(node->transitions.sparse.children);
            break;
    }
    kmem_cache_free(strider_ac_node_cache, node);
}

static void strider_ac_destroy(struct strider_ac *ac) {
    LIST_HEAD(queue);
    list_add_tail(&ac->root->list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, list);
        list_del(&node->list);

        if (node->transitions_type == STRIDER_AC_TRANSITIONS_LINKED) {
            struct strider_ac_linked_transition *tsn;
            list_for_each_entry(tsn, &node->transitions.linked, list)
                list_add_tail(&tsn->next->list, &queue);
        } else {
            for (u16 i = 0; i < node->num_children; ++i) {
                struct strider_ac_node *child = node->transitions_type == STRIDER_AC_TRANSITIONS_DENSE
                                                    ? node->transitions.dense.children[i]
                                                    : node->transitions.sparse.children[i];
                if (child)
                    list_add_tail(&child->list, &queue);
            }
        }

        strider_ac_node_destroy(node);
    }
    kfree(ac);
}

static void strider_ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    strider_ac_destroy(ac);
}

static struct strider_ac_node *strider_ac_node_add_next(struct strider_ac_node *node, u8 byte, gfp_t gfp_mask) {
    struct strider_ac_linked_transition *tsn;

    list_for_each_entry(tsn, &node->transitions.linked, list) {
        if (tsn->byte == byte)
            return tsn->next;
    }

    tsn = kmem_cache_alloc(strider_ac_linked_transition_cache, gfp_mask);
    if (!tsn)
        return ERR_PTR(-ENOMEM);
    tsn->next = strider_ac_node_create(gfp_mask);
    if (!tsn->next) {
        kmem_cache_free(strider_ac_linked_transition_cache, tsn);
        return ERR_PTR(-ENOMEM);
    }
    tsn->byte = byte;
    list_add(&tsn->list, &node->transitions.linked);
    return tsn->next;
}

static int strider_ac_node_finalize_dense(struct strider_ac_node *node, gfp_t gfp_mask) {
    struct strider_ac_node **children = kcalloc(STRIDER_AC_ALPHABET_SIZE, sizeof(*children), gfp_mask);
    if (!children)
        return -ENOMEM;
    struct strider_ac_linked_transition *tsn;
    list_for_each_entry(tsn, &node->transitions.linked, list)
        children[tsn->byte] = tsn->next;
    node->transitions_type = STRIDER_AC_TRANSITIONS_DENSE;
    node->transitions.dense.children = children;
    node->num_children = STRIDER_AC_ALPHABET_SIZE;
    return 0;
}

static int strider_ac_linked_transition_compare(void *priv, const struct list_head *a, const struct list_head *b) {
    const struct strider_ac_linked_transition *tsn_a = list_entry(a, struct strider_ac_linked_transition, list);
    const struct strider_ac_linked_transition *tsn_b = list_entry(b, struct strider_ac_linked_transition, list);
    return tsn_a->byte - tsn_b->byte;
}

static int strider_ac_node_finalize_sparse(struct strider_ac_node *node, u16 num_tsn, gfp_t gfp_mask) {
    u8 *bytes = kmalloc_array(num_tsn, sizeof(*bytes), gfp_mask);
    if (!bytes)
        return -ENOMEM;
    struct strider_ac_node **children = kmalloc_array(num_tsn, sizeof(*children), gfp_mask);
    if (!children) {
        kfree(bytes);
        return -ENOMEM;
    }

    list_sort(NULL, &node->transitions.linked, strider_ac_linked_transition_compare);
    u16 i = 0;
    struct strider_ac_linked_transition *tsn, *tmp;
    list_for_each_entry_safe(tsn, tmp, &node->transitions.linked, list) {
        bytes[i] = tsn->byte;
        children[i] = tsn->next;
        ++i;
        list_del(&tsn->list);
        kmem_cache_free(strider_ac_linked_transition_cache, tsn);
    }

    node->transitions_type = STRIDER_AC_TRANSITIONS_SPARSE;
    node->transitions.sparse.bytes = bytes;
    node->transitions.sparse.children = children;
    node->num_children = i;

    return 0;
}

static int strider_ac_byte_compare(const void *a, const void *b) {
    return *(u8 *) a - *(u8 *) b;
}

static struct strider_ac_node *strider_ac_node_find_next(const struct strider_ac_node *node, u8 byte) {
    switch (node->transitions_type) {
        case STRIDER_AC_TRANSITIONS_DENSE:
            return node->transitions.dense.children[byte];
        case STRIDER_AC_TRANSITIONS_SPARSE: {
            const u8 *pb = bsearch(&byte, node->transitions.sparse.bytes, node->num_children, sizeof(byte),
                                   strider_ac_byte_compare);
            if (pb)
                return node->transitions.sparse.children[pb - node->transitions.sparse.bytes];
            fallthrough;
        }
        default:
            return NULL;
    }
}

static struct strider_ac_node *strider_ac_node_find_failure(const struct strider_ac_node *parent, u8 byte) {
    const struct strider_ac_node *node;
    for (node = parent->failure; node != node->failure; node = node->failure) {
        struct strider_ac_node *next = strider_ac_node_find_next(node, byte);
        if (next)
            return next;
    }
    // node is now root
    return strider_ac_node_find_next(node, byte);
}

static int strider_ac_finalize_nodes(struct strider_ac_node *root, gfp_t gfp_mask) {
    strider_ac_node_finalize_dense(root, gfp_mask); // always make dense transitions for root
    LIST_HEAD(queue);
    for (u16 i = 0; i < root->num_children; ++i) {
        struct strider_ac_node *child = root->transitions.dense.children[i];
        if (child)
            list_add_tail(&child->list, &queue);
    }
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, list);
        list_del(&node->list);

        u16 count = 0;
        struct strider_ac_linked_transition *tsn;
        list_for_each_entry(tsn, &node->transitions.linked, list)
            ++count;
        if (count > 0) {
            int ret = count > STRIDER_AC_TRANSITIONS_SPARSE_LIMIT
                          ? strider_ac_node_finalize_dense(node, gfp_mask)
                          : strider_ac_node_finalize_sparse(node, count, gfp_mask);
            if (ret < 0) {
                struct strider_ac_node *tmp;
                // clear the in-flight traversal queue
                list_for_each_entry_safe(node, tmp, &queue, list)
                    list_del(&node->list);
                return ret;
            }
        }

        for (u16 i = 0; i < node->num_children; ++i) {
            struct strider_ac_node *child = node->transitions_type == STRIDER_AC_TRANSITIONS_DENSE
                                                ? node->transitions.dense.children[i]
                                                : node->transitions.sparse.children[i];
            if (child)
                list_add_tail(&child->list, &queue);
        }
    }
    return 0;
}

static void strider_ac_build_links(struct strider_ac_node *root) {
    root->failure = root;
    LIST_HEAD(queue);
    // point root's children's failure links to root
    for (u16 i = 0; i < root->num_children; ++i) {
        struct strider_ac_node *child = root->transitions.dense.children[i];
        if (child) {
            child->failure = root;
            list_add_tail(&child->list, &queue);
        }
    }
    while (!list_empty(&queue)) {
        struct strider_ac_node *node = list_first_entry(&queue, struct strider_ac_node, list);
        list_del(&node->list);
        for (u16 i = 0; i < node->num_children; ++i) {
            struct strider_ac_node *child = node->transitions_type == STRIDER_AC_TRANSITIONS_DENSE
                                                ? node->transitions.dense.children[i]
                                                : node->transitions.sparse.children[i];
            if (child) {
                u8 byte = node->transitions_type == STRIDER_AC_TRANSITIONS_DENSE
                              ? i
                              : node->transitions.sparse.bytes[i];
                struct strider_ac_node *failure_node = strider_ac_node_find_failure(node, byte);
                child->failure = failure_node ? failure_node : root;
                child->output_link = list_empty(&child->failure->outputs)
                                         ? child->failure->output_link
                                         : child->failure;
                list_add_tail(&child->list, &queue);
            }
        }
    }
}

struct strider_ac *strider_ac_create(gfp_t gfp_mask) {
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
        node = strider_ac_node_add_next(node, target->pattern[i], gfp_mask);
        if (IS_ERR(node))
            return PTR_ERR(node);
    }
    list_add(&target->list, &node->outputs);
    return 0;
}

int strider_ac_compile(struct strider_ac *ac, gfp_t gfp_mask) {
    int ret = strider_ac_finalize_nodes(ac->root, gfp_mask);
    if (ret < 0)
        return ret;
    strider_ac_build_links(ac->root);
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
            const struct strider_ac_node *next = strider_ac_node_find_next(node, data[i]);
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
