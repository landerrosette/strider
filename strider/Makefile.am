all-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir)

clean-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir) clean

install-exec-local:
	$(MAKE) -C $(kbuilddir) M=$(abs_srcdir) STRIDER_ABS_TOP_SRCDIR=$(abs_top_srcdir) INSTALL_MOD_PATH=$(DESTDIR) modules_install
