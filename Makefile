CC ?= cc

CFLAGS += -g -Wall -std=c99 -pedantic
LDFLAGS += -ldl

OBJS = main.o psyscall.o

all: psyscall

psyscall: main.o psyscall.o
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

main.o: main.c sysheaders.h
	echo "#include <sys/syscall.h>" | $(CC) -dM -E - \
		| sed -n 's/#define __NR_\([^ ]*\) .*/{"\1", __NR_\1},/p' \
		| env LC_COLLATE=C sort > syscalls.inc
	echo "#define NULL 0" | cat sysheaders.h - | $(CC) -dM -E - \
		| sed -n 's/#define \([^_][A-Z0-9_]\+\) \(0x[0-9A-Fa-f]\+\|[0-9]\+\)$$/{"\1", (long)(\2)},/p' \
		| env LC_COLLATE=C sort > constants.inc
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) psyscall *.inc *.o

.PHONY: all clean
