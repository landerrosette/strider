/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright (C) 2025-2026 landerrosette
 */

#ifndef STRIDER_STRIDER_H
#define STRIDER_STRIDER_H

#include <linux/types.h>

struct strider_set;

struct net;
struct sk_buff;

struct strider_set *strider_set_get(struct net *net, const char *set_name);
void strider_set_put(struct strider_set *set);
bool strider_match_skb(const struct strider_set *set, struct sk_buff *skb, unsigned int from, unsigned int to);

#endif // STRIDER_STRIDER_H
