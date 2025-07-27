KDIR ?= /lib/modules/`uname -r`/build

.PHONY: all clean install ac_test

all:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

install: all
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
	depmod -a

ac_test:
	$(MAKE) -C $(KDIR) M=$$PWD CONFIG_STRIDER_AC_TEST=m
	@if [ -f $$PWD/strider_ac_test-out.ko ]; then \
		mv $$PWD/strider_ac_test-out.ko $$PWD/strider_ac_test.ko; \
	fi
