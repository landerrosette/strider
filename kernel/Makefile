KDIR ?= /lib/modules/`uname -r`/build

.PHONY: all
all:
	$(MAKE) -C $(KDIR) M=$$PWD modules

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

.PHONY: install
install: all
	sudo $(MAKE) -C $(KDIR) M=$$PWD modules_install
	sudo depmod -a
