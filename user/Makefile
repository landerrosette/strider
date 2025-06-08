TARGET := striderctl
SRCS := striderctl.c
OBJS := $(patsubst %.c, %.o, $(SRCS))
DEPS := $(patsubst %.c, %.d, $(SRCS))

CC := gcc
CFLAGS ?= -Wall -Wextra -g
CPPFLAGS += -I../include
LDLIBS := -lnl-3 -lnl-genl-3

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@ -MMD -MP

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
