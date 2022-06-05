ifneq ($(KERNELRELEASE),)
    obj-m := wdum_filter.o wdum_rules.o
    wdum_filter-objs := set_filter.o matchers.o logging.o
    wdum_rules-objs := rule_base.o user_comm.o logging.o

else
    
    KERNELDIR ?= /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif
