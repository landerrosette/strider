#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H


#include <linux/list.h>
#include <linux/skbuff.h>

struct ac_automaton;

struct ac_rule {
    struct list_head list;
    const char *pattern;
    size_t len;
    void *priv;
};

struct ac_automaton * __must_check ac_automaton_build(struct list_head *head);

void ac_automaton_free(struct ac_automaton *automaton);

int ac_automaton_match(struct ac_automaton *automaton, const struct sk_buff *skb, size_t offset, size_t len,
                       int (*cb)(void *priv, size_t offset, void *cb_ctx), void *cb_ctx);


#endif //AHO_CORASICK_H
