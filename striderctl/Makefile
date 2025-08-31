PROGRAM_NAME := striderctl
PROGRAM_VER := 0.2.0
SRCS := striderctl.c

TARGET := $(PROGRAM_NAME)
CC ?= gcc
CFLAGS ?= -Wall -Wextra -g -O2
CPPFLAGS += -DPROGRAM_NAME="\"$(PROGRAM_NAME)\"" -DPROGRAM_VER="\"$(PROGRAM_VER)\""
CPPFLAGS += -I../include $(shell pkg-config --cflags libnl-genl-3.0)
LDLIBS := $(shell pkg-config --libs libnl-genl-3.0)
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)
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
