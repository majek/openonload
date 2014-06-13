TARGETS		:= rx_timestamping tx_timestamping

# Turning on high warning level
MMAKE_CFLAGS	:= -fno-strict-aliasing -W -Wall -Wunused-parameter \
		   -Wunused-function -Wunused-label -Wpointer-arith \
		   -Wformat -Wreturn-type -Wsign-compare -Wmultichar \
		   -Wformat-nonliteral -Winit-self -Wuninitialized \
		   -Wformat-security -Werror -g -O

MMAKE_CFLAGS    += -I../../../include

CC		:= gcc

# Use the kernel timestamping headers for definition, unless they don't exist
# in which case we will fall back to our own definitions.
# We need both these two files to exist:
ts_missing =
  ifeq (,$(wildcard /usr/include/linux/net_tstamp.h))
    ts_missing = yes
  endif
  ifeq (,$(wildcard /usr/include/linux/sockios.h))
    ts_missing = yes
  endif
ifdef ts_missing
  MMAKE_CFLAGS += -DNO_KERNEL_TS_INCLUDE
endif

%.o: %.c
	@$(CC) $(MMAKE_CFLAGS) -c $^

all: $(TARGETS)

rx_timestamping: rx_timestamping.o
	@$(CC) $(MMAKE_CFLAGS) $^ -o $@

tx_timestamping: tx_timestamping.o
	@$(CC) $(MMAKE_CFLAGS) $^ -o $@

targets:
	@echo $(TARGETS)

clean:
	@rm *.o $(TARGETS)
