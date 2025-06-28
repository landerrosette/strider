.PHONY: all kmod cli clean install

all: kmod cli

kmod cli:
	$(MAKE) -C $@

clean:
	$(MAKE) -C kmod clean
	$(MAKE) -C cli clean

install: all
	$(MAKE) -C kmod install
	$(MAKE) -C cli install
