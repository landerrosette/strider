/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright (C) 2025-2026 landerrosette <57791410+landerrosette@users.noreply.github.com>
 */

#ifndef STRIDER_NETLINK_H
#define STRIDER_NETLINK_H

#include <linux/init.h>

int __init strider_netlink_init(void);
void strider_netlink_exit(void);

#endif // STRIDER_NETLINK_H
