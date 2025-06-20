#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H


#include <linux/compiler_attributes.h>
#include <linux/list.h>
#include <linux/types.h>

struct ac_automaton;
struct ac_node;

// Represents a single input unit (a pattern) for the automaton.
struct ac_input {
    struct list_head list;
    const char *pattern;
    size_t len;
    void *priv; // caller's private context pointer, returned verbatim on match
};

struct ac_match_state {
    struct ac_node *current_state;
    size_t stream_pos; // position in the logical input stream
};

struct ac_automaton * __must_check ac_automaton_build(struct list_head *inputs_head);

void ac_automaton_free(struct ac_automaton *automaton);

void ac_match_state_init(struct ac_automaton *automaton, struct ac_match_state *state);

void ac_automaton_feed(struct ac_match_state *state, const u8 *data, size_t len,
                       int (*cb)(void *priv, size_t offset, void *cb_ctx), void *cb_ctx);


#endif //AHO_CORASICK_H
