# SPDX-License-Identifier: GPL-2.0-only

# Copyright (C) 2025-2026 landerrosette <57791410+landerrosette@users.noreply.github.com>

xtlib_LTLIBRARIES = libxt_strider.la

AM_CFLAGS = -Wall
libxt_strider_la_CPPFLAGS = -I$(top_srcdir)/include $(libxtables_CFLAGS)
libxt_strider_la_LIBADD = $(libxtables_LIBS)
libxt_strider_la_LDFLAGS = -module -avoid-version

all-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir)

clean-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir) clean

install-exec-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir) INSTALL_MOD_PATH=$(DESTDIR) modules_install
