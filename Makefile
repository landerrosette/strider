MODULE_NAME ?= strider
KDIR ?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD modules

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

install: all
	sudo $(MAKE) -C $(KDIR) M=$$PWD modules_install
	sudo depmod -a

uninstall:
	sudo modprobe -r $(MODULE_NAME) || true
	sudo rm -f /lib/modules/`uname -r`/extra/$(MODULE_NAME).ko
	sudo depmod -a

.PHONY: all clean install uninstall
