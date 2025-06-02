KDIR ?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD modules

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

install: all
	sudo $(MAKE) -C $(KDIR) M=$$PWD modules_install
	sudo depmod -a

.PHONY: all clean install
