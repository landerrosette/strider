TARGET := striderctl
SRCS := striderctl.c
OBJS := $(patsubst %.c, %.o, $(SRCS))
DEPS := $(patsubst %.c, %.d, $(SRCS))

CC := gcc
CFLAGS ?= -Wall -Wextra -g
CPPFLAGS += -I../include $(shell pkg-config --cflags libnl-genl-3.0)
LDLIBS := $(shell pkg-config --libs libnl-genl-3.0)

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@ -MMD -MP

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
