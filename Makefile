SUBDIRS := strider striderctl xt_strider

.PHONY: all $(SUBDIRS) clean install

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean install:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done

install: all
