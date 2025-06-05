CC      := gcc
AR      := ar
CFLAGS  := -Wall -Wextra -Werror -MMD -MP
ARFLAGS := rcs

lib     := libfs.a
SRCS    := disk.c fs.c
OBJS    := $(SRCS:.c=.o)
DEPS    := $(SRCS:.c=.d)

.PHONY: all clean

all: $(lib)

$(lib): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(lib)