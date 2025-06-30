#ifndef STRIDER_AHO_CORASICK_H
#define STRIDER_AHO_CORASICK_H


#include <linux/compiler_attributes.h>
#include <linux/list.h>
#include <linux/types.h>

// Represents a single input unit (a pattern) for the automaton.
struct strider_ac_input {
    struct list_head list;
    const char *pattern;
    size_t len;
    const void *priv; // caller's private context pointer, returned verbatim on match
};

struct strider_ac_automaton;

struct strider_ac_node;

struct strider_ac_match_state {
    const struct strider_ac_node *current_state;
    size_t stream_pos; // position in the logical input stream
};

struct strider_ac_automaton * __must_check strider_ac_automaton_build(struct list_head *inputs);

void strider_ac_automaton_free(struct strider_ac_automaton *automaton);

void strider_ac_match_state_init(const struct strider_ac_automaton *automaton, struct strider_ac_match_state *state);

/**
 * ac_automaton_feed
 *
 * Return: 0 on successful processing of all data.
 *         Otherwise, returns a non-zero value propagated from the callback, stopping further processing.
 *         Conventionally, negative values indicate errors (e.g., -ENOMEM),
 *         while positive values signal other non-error conditions for stopping (e.g., a specific match found).
 */
int strider_ac_automaton_feed(struct strider_ac_match_state *state, const u8 *data, size_t len,
                              int (*cb)(const void *priv, size_t offset, void *cb_ctx), void *cb_ctx);


#endif //STRIDER_AHO_CORASICK_H
