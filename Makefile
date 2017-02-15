CC ?= cc

CFLAGS += -g -Wall -std=c99 -pedantic
LDFLAGS +=

all: psyscall

psyscall: main.o psyscall.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

main.o: main.c sysheaders.h
	echo "#include <sys/syscall.h>" | $(CC) -dM -E - \
		| sed -n 's/#define __NR_\([^ ]*\) .*/{"\1", __NR_\1},/p' \
		| env LC_ALL=C sort > syscalls.inc
	cat sysheaders.h | $(CC) -dM -E - \
		| sed -n 's/#define \([^_][A-Z0-9_]\+\) \(0x[0-9A-Fa-f]\+\|[0-9]\+\)$$/{"\1", (long)\2},/p' \
		| env LC_ALL=C sort > constants.inc
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) psyscall *.inc *.o

.PHONY: all clean
