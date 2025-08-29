KDIR ?= /lib/modules/`uname -r`/build

.PHONY: all clean install

all:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

install: all
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
	depmod -a
