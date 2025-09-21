#include "ac.h"

#include <linux/align.h>
#include <linux/bug.h>
#include <linux/container_of.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#define STRIDER_AC_ALPHABET_SIZE 256
#define STRIDER_AC_TRANSITIONS_DENSE_THRESHOLD 16
#define STRIDER_AC_TRANSITIONS_ALWAYS_DENSE_DEPTH_LIMIT 1

struct strider_ac_node {
    union {
        struct {
            struct strider_ac_node **children; // array of size STRIDER_AC_ALPHABET_SIZE
        } dense;

        struct {
            u8 *bytes;
            struct strider_ac_node **children;
        } sparse;
    } transitions;

    enum {
        STRIDER_AC_TRANSITIONS_DENSE,
        STRIDER_AC_TRANSITIONS_SPARSE,
    } transitions_type;

    u16 num_children;
    struct strider_ac_node *failure;
    struct list_head outputs; // list of struct strider_ac_target
    struct strider_ac_node *output_link;
};

struct strider_ac_build_node {
    struct list_head list;
    size_t depth;
    struct list_head transitions; // list of struct strider_ac_build_transition
    u16 num_children;
    struct list_head outputs;
    struct strider_ac_node *final;
};

struct strider_ac_build_transition {
    struct list_head list;
    struct strider_ac_build_node *next;
    u8 byte;
};

struct strider_ac_arena {
    void *head;
    u8 *bump;
    size_t size;
};

struct strider_ac {
    union {
        struct strider_ac_node *final;
        struct strider_ac_build_node *build;
    } root;

    bool compiled;
    struct strider_ac_arena arena;
    struct rcu_head rcu;
};

static struct kmem_cache *strider_ac_build_node_cache;
static struct kmem_cache *strider_ac_build_transition_cache;

static struct strider_ac_build_node *strider_ac_build_node_create(size_t depth, gfp_t gfp_mask) {
    struct strider_ac_build_node *bnode = kmem_cache_zalloc(strider_ac_build_node_cache, gfp_mask);
    if (!bnode)
        return NULL;
    bnode->depth = depth;
    INIT_LIST_HEAD(&bnode->transitions);
    INIT_LIST_HEAD(&bnode->outputs);
    return bnode;
}

static void strider_ac_build_trie_destroy(struct strider_ac_build_node *broot) {
    LIST_HEAD(queue);
    list_add_tail(&broot->list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_build_node *node = list_first_entry(&queue, struct strider_ac_build_node, list);
        list_del(&node->list);
        struct strider_ac_build_transition *tsn, *tmp;
        list_for_each_entry_safe(tsn, tmp, &node->transitions, list) {
            list_add_tail(&tsn->next->list, &queue);
            list_del(&tsn->list);
            kmem_cache_free(strider_ac_build_transition_cache, tsn);
        }
        kmem_cache_free(strider_ac_build_node_cache, node);
    }
}

static void strider_ac_destroy(struct strider_ac *ac) {
    if (!ac->compiled)
        strider_ac_build_trie_destroy(ac->root.build);
    else
        vfree(ac->arena.head);
    kfree(ac);
}

static void strider_ac_destroy_rcu_cb(struct rcu_head *rcu) {
    struct strider_ac *ac = container_of(rcu, struct strider_ac, rcu);
    strider_ac_destroy(ac);
}

static struct strider_ac_build_node *strider_ac_build_node_add_child(struct strider_ac_build_node *bnode, u8 byte,
                                                                     gfp_t gfp_mask) {
    struct strider_ac_build_transition *tsn;

    list_for_each_entry(tsn, &bnode->transitions, list) {
        if (tsn->byte == byte)
            return tsn->next;
    }

    tsn = kmem_cache_alloc(strider_ac_build_transition_cache, gfp_mask);
    if (!tsn)
        return ERR_PTR(-ENOMEM);
    tsn->next = strider_ac_build_node_create(bnode->depth + 1, gfp_mask);
    if (!tsn->next) {
        kmem_cache_free(strider_ac_build_transition_cache, tsn);
        return ERR_PTR(-ENOMEM);
    }
    tsn->byte = byte;
    list_add(&tsn->list, &bnode->transitions);
    ++bnode->num_children;
    return tsn->next;
}

static size_t strider_ac_compute_size(struct strider_ac_build_node *broot) {
    size_t ret = 0;
    LIST_HEAD(queue);
    list_add_tail(&broot->list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_build_node *bnode = list_first_entry(&queue, struct strider_ac_build_node, list);
        list_del(&bnode->list);
        ret += ALIGN(sizeof(struct strider_ac_node), sizeof(void *));
        if (bnode->num_children >= STRIDER_AC_TRANSITIONS_DENSE_THRESHOLD ||
            bnode->depth <= STRIDER_AC_TRANSITIONS_ALWAYS_DENSE_DEPTH_LIMIT) {
            ret += ALIGN(STRIDER_AC_ALPHABET_SIZE * sizeof(struct strider_ac_node *), sizeof(void *));
        } else if (bnode->num_children > 0) {
            ret += ALIGN(bnode->num_children * sizeof(u8), sizeof(void *));
            ret += ALIGN(bnode->num_children * sizeof(struct strider_ac_node *), sizeof(void *));
        }
        struct strider_ac_build_transition *tsn;
        list_for_each_entry(tsn, &bnode->transitions, list)
            list_add_tail(&tsn->next->list, &queue);
    }
    return ret;
}

static void *strider_ac_arena_alloc(struct strider_ac_arena *arena, size_t size) {
    size = ALIGN(size, sizeof(void *));
    if (arena->bump + size > (u8 *) arena->head + arena->size) {
        WARN_ON(1);
        return NULL;
    }
    void *ret = arena->bump;
    arena->bump += size;
    return ret;
}

static void *strider_ac_arena_zalloc(struct strider_ac_arena *arena, size_t size) {
    void *ret = strider_ac_arena_alloc(arena, size);
    if (ret)
        memset(ret, 0, size);
    return ret;
}

static int strider_ac_finalize_nodes(struct strider_ac_arena *arena, struct strider_ac_build_node *broot) {
    struct strider_ac_node *root = strider_ac_arena_zalloc(arena, sizeof(*root));
    if (!root)
        return -ENOSPC;
    broot->final = root;
    LIST_HEAD(queue);
    list_add_tail(&broot->list, &queue);
    while (!list_empty(&queue)) {
        struct strider_ac_build_node *bnode = list_first_entry(&queue, struct strider_ac_build_node, list);
        list_del(&bnode->list);

        if (bnode->num_children >= STRIDER_AC_TRANSITIONS_DENSE_THRESHOLD ||
            bnode->depth <= STRIDER_AC_TRANSITIONS_ALWAYS_DENSE_DEPTH_LIMIT) {
            struct strider_ac_node **children = strider_ac_arena_zalloc(
                arena, STRIDER_AC_ALPHABET_SIZE * sizeof(*children));
            if (!children)
                goto fail;
            struct strider_ac_build_transition *tsn;
            list_for_each_entry(tsn, &bnode->transitions, list) {
                struct strider_ac_node *child = strider_ac_arena_zalloc(arena, sizeof(*child));
                if (!child)
                    goto fail;
                children[tsn->byte] = child;
                tsn->next->final = child;
                list_add_tail(&tsn->next->list, &queue);
            }
            bnode->final->transitions.dense.children = children;
            bnode->final->transitions_type = STRIDER_AC_TRANSITIONS_DENSE;
            bnode->final->num_children = STRIDER_AC_ALPHABET_SIZE;
        } else if (bnode->num_children > 0) {
            u8 *bytes = strider_ac_arena_alloc(arena, bnode->num_children * sizeof(*bytes));
            if (!bytes)
                goto fail;
            struct strider_ac_node **children = strider_ac_arena_alloc(arena, bnode->num_children * sizeof(*children));
            if (!children)
                goto fail;
            u16 i = 0;
            struct strider_ac_build_transition *tsn;
            list_for_each_entry(tsn, &bnode->transitions, list) {
                struct strider_ac_node *child = strider_ac_arena_zalloc(arena, sizeof(*child));
                if (!child)
                    goto fail;
                bytes[i] = tsn->byte;
                children[i] = child;
                ++i;
                tsn->next->final = child;
                list_add_tail(&tsn->next->list, &queue);
            }
            bnode->final->transitions.sparse.bytes = bytes;
            bnode->final->transitions.sparse.children = children;
            bnode->final->transitions_type = STRIDER_AC_TRANSITIONS_SPARSE;
            bnode->final->num_children = bnode->num_children;
        }

        list_replace(&bnode->outputs, &bnode->final->outputs);
    }
    return 0;

fail: {
        struct strider_ac_build_node *bnode, *tmp;
        // clear the in-flight traversal queue
        list_for_each_entry_safe(bnode, tmp, &queue, list)
            list_del(&bnode->list);
        return -ENOSPC;
    }
}

static struct strider_ac_node *strider_ac_node_find_next(const struct strider_ac_node *node, u8 byte) {
    if (node->num_children > 0) {
        switch (node->transitions_type) {
            case STRIDER_AC_TRANSITIONS_DENSE:
                return node->transitions.dense.children[byte];
            case STRIDER_AC_TRANSITIONS_SPARSE:
                for (u16 i = 0; i < node->num_children; ++i) {
                    if (node->transitions.sparse.bytes[i] == byte)
                        return node->transitions.sparse.children[i];
                }
        }
    }
    return NULL;
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

static void strider_ac_link_nodes(struct strider_ac_build_node *broot) {
    struct strider_ac_node *root = broot->final;
    broot->final->failure = root;
    LIST_HEAD(queue);
    struct strider_ac_build_transition *tsn;
    list_for_each_entry(tsn, &broot->transitions, list) {
        struct strider_ac_node *child = tsn->next->final;
        child->failure = root;
        list_add_tail(&tsn->next->list, &queue);
    }
    while (!list_empty(&queue)) {
        struct strider_ac_build_node *bnode = list_first_entry(&queue, struct strider_ac_build_node, list);
        list_del(&bnode->list);
        list_for_each_entry(tsn, &bnode->transitions, list) {
            struct strider_ac_node *child = tsn->next->final;
            struct strider_ac_node *failure_node = strider_ac_node_find_failure(bnode->final, tsn->byte);
            child->failure = failure_node ? failure_node : root;
            child->output_link = list_empty(&child->failure->outputs) ? child->failure->output_link : child->failure;
            list_add_tail(&tsn->next->list, &queue);
        }
    }
}

int strider_ac_caches_create(void) {
    strider_ac_build_node_cache = KMEM_CACHE(strider_ac_build_node, SLAB_HWCACHE_ALIGN);
    if (!strider_ac_build_node_cache)
        return -ENOMEM;
    strider_ac_build_transition_cache = KMEM_CACHE(strider_ac_build_transition, SLAB_HWCACHE_ALIGN);
    if (!strider_ac_build_transition_cache) {
        kmem_cache_destroy(strider_ac_build_node_cache);
        return -ENOMEM;
    }
    return 0;
}

void strider_ac_caches_destroy(void) {
    kmem_cache_destroy(strider_ac_build_transition_cache);
    kmem_cache_destroy(strider_ac_build_node_cache);
}

struct strider_ac *strider_ac_create(gfp_t gfp_mask) {
    struct strider_ac *ac = kzalloc(sizeof(*ac), gfp_mask);
    if (!ac)
        return ERR_PTR(-ENOMEM);
    ac->root.build = strider_ac_build_node_create(0, gfp_mask);
    if (!ac->root.build) {
        kfree(ac);
        return ERR_PTR(-ENOMEM);
    }
    return ac;
}

void strider_ac_schedule_destroy(struct strider_ac *ac) {
    call_rcu(&ac->rcu, strider_ac_destroy_rcu_cb);
}

int strider_ac_add_target(struct strider_ac *ac, struct strider_ac_target *target, gfp_t gfp_mask) {
    struct strider_ac_build_node *bnode = ac->root.build;
    for (size_t i = 0; i < target->pattern_len; ++i) {
        bnode = strider_ac_build_node_add_child(bnode, target->pattern[i], gfp_mask);
        if (IS_ERR(bnode))
            return PTR_ERR(bnode);
    }
    list_add(&target->list, &bnode->outputs);
    return 0;
}

int strider_ac_compile(struct strider_ac *ac) {
    struct strider_ac_build_node *broot = ac->root.build;
    ac->arena.size = strider_ac_compute_size(broot);
    ac->arena.head = vmalloc(ac->arena.size);
    if (!ac->arena.head)
        return -ENOMEM;
    ac->arena.bump = ac->arena.head;
    int ret = strider_ac_finalize_nodes(&ac->arena, broot);
    if (ret < 0) {
        vfree(ac->arena.head);
        return ret;
    }
    strider_ac_link_nodes(broot);
    ac->root.final = broot->final;
    ac->compiled = true;
    strider_ac_build_trie_destroy(broot);
    return 0;
}

void strider_ac_match_init(const struct strider_ac *ac, struct strider_ac_match_state *state) {
    state->cursor = ac->root.final;
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
