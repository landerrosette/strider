#ifndef STRIDER_AC_H
#define STRIDER_AC_H


#include <linux/compiler.h>
#include <linux/types.h>

struct strider_ac_automaton;

struct ac_node;

struct strider_ac_match_state {
    const struct ac_node *cursor;
    const struct strider_ac_automaton *automaton;
    size_t stream_pos; // position in the logical input stream
};

struct strider_ac_automaton * __cold __must_check strider_ac_automaton_compile(const char *const *patterns, size_t num_patterns);

/**
 * strider_ac_automaton_destroy() - Destroy an automaton synchronously.
 */
void __cold strider_ac_automaton_destroy(struct strider_ac_automaton *automaton);

/**
 * strider_ac_automaton_destroy_rcu() - Schedule the destruction of an automaton via RCU.
 */
void __cold strider_ac_automaton_destroy_rcu(struct strider_ac_automaton *automaton);

void strider_ac_match_state_init(struct strider_ac_match_state *state, const struct strider_ac_automaton *automaton);

/**
 * strider_ac_automaton_scan()
 *
 * Return: 0 on successful processing of all data.
 *         Otherwise, returns a non-zero value propagated from the callback, stopping further processing.
 *         Conventionally, negative values indicate errors (e.g., -ENOMEM),
 *         while positive values signal other non-error conditions for stopping (e.g., a specific match found).
 */
int strider_ac_automaton_scan(struct strider_ac_match_state *state, const u8 *data, size_t len,
                              int (*cb)(void *cb_ctx), void *cb_ctx);


#endif //STRIDER_AC_H
