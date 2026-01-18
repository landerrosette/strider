# SPDX-License-Identifier: GPL-2.0-only

# Copyright (C) 2025-2026 landerrosette

all-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir)

clean-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir) clean

install-exec-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir) INSTALL_MOD_PATH=$(DESTDIR) modules_install
