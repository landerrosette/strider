SUBDIRS := strider cli

.PHONY: all $(SUBDIRS) clean install

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean install:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done

install: all
