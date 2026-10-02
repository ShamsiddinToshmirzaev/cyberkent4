CC      ?= gcc
CFLAGS  := -O2 -std=gnu11 -Wall -Wextra -fPIE -fstack-protector-all
LDFLAGS := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

SRC := src/server/main.c \
       src/protocol/protocol.c \
       src/vm/vm.c \
       src/vm/verifier.c

all: chall chall_dbg

chall: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o $@ $(SRC)

chall_dbg: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

clean:
	rm -f chall chall_dbg

.PHONY: all clean
