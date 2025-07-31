#ifndef STRIDER_AHO_CORASICK_H
#define STRIDER_AHO_CORASICK_H


#include <linux/compiler_attributes.h>
#include <linux/types.h>

struct strider_ac_automaton;

struct ac_node;
struct strider_ac_match_state {
    const struct ac_node *cursor;
    const struct strider_ac_automaton *automaton;
    size_t stream_pos; // position in the logical input stream
};

struct strider_ac_automaton * __must_check strider_ac_automaton_build(const char * const *patterns, size_t num_patterns);

void strider_ac_automaton_destroy(struct strider_ac_automaton *automaton);

void strider_ac_match_state_init(struct strider_ac_match_state *state, const struct strider_ac_automaton *automaton);

/**
 * ac_automaton_feed
 *
 * Return: 0 on successful processing of all data.
 *         Otherwise, returns a non-zero value propagated from the callback, stopping further processing.
 *         Conventionally, negative values indicate errors (e.g., -ENOMEM),
 *         while positive values signal other non-error conditions for stopping (e.g., a specific match found).
 */
int strider_ac_automaton_feed(struct strider_ac_match_state *state, const u8 *data, size_t len,
                              int (*cb)(void *cb_ctx), void *cb_ctx);


#endif //STRIDER_AHO_CORASICK_H
