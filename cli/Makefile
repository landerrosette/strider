TARGET := striderctl
SRCS := main.c
OBJS := $(patsubst %.c, %.o, $(SRCS))
DEPS := $(patsubst %.c, %.d, $(SRCS))

CC := gcc
CFLAGS ?= -Wall -Wextra -g
CPPFLAGS += -I../include $(shell pkg-config --cflags libnl-genl-3.0)
LDLIBS := $(shell pkg-config --libs libnl-genl-3.0)

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/sbin

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@ -MMD -MP

clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)

install: all
	install -d ${DESTDIR}$(BINDIR)
	install -m 755 $(TARGET) ${DESTDIR}$(BINDIR)/

-include $(DEPS)
