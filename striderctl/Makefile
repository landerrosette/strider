PROGRAM := striderctl
VERSION := 0.2.0
SRCS := striderctl.c

CC := gcc
CFLAGS ?= -Wall -Wextra -g -O2
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/sbin

OBJS := $(patsubst %.c, %.o, $(SRCS))
DEPS := $(patsubst %.c, %.d, $(SRCS))
CPPFLAGS += -DPROGRAM="\"$(PROGRAM)\"" -DVERSION="\"$(VERSION)\""
CPPFLAGS += -I../include $(shell pkg-config --cflags libnl-genl-3.0)
LDLIBS := $(shell pkg-config --libs libnl-genl-3.0)

.PHONY: all clean install

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@ -MMD -MP

clean:
	rm -f $(PROGRAM) $(OBJS) $(DEPS)

install: all
	install -d ${DESTDIR}$(BINDIR)
	install -m 755 $(PROGRAM) ${DESTDIR}$(BINDIR)/

-include $(DEPS)
