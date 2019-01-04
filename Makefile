CFLAGS ?= -g
CFLAGS += -Wall -std=c89 -pedantic

all: psyscall

psyscall: main.o psyscall.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

syscalls.inc:
	# Parse syscall numbers from sys/syscall.h header.
	echo "#include <sys/syscall.h>" \
		| $(CC) -dM -E - \
		| sed -n 's/^#define __NR_\([^ ]*\) .*$$/{"\1", __NR_\1},/p' \
		| env LC_ALL=C sort >"$@"

constants.inc: sysheaders.h
	# Filter out bad headers (for example, non-existent header files) if
	# preprocessing of all sysheaders.h includes does not succeed. Then,
	# generate constant values from the remaining good system headers.
	if $(CC) -E "$<" >/dev/null; then $(CC) -dM -E "$<"; else \
		while IFS= read -r inc; \
		do echo "$$inc" | $(CC) -E - >/dev/null && echo "$$inc"; \
		done <"$<" | $(CC) -dM -E -; \
	fi 2>/dev/null \
		| sed -nr 's/^#define ([^_][A-Z0-9_]+) (0x[0-9A-Fa-f]+|[0-9]+)$$/{"\1", (long)\2},/p' \
		| env LC_ALL=C sort >"$@"

main.o: main.c syscalls.inc constants.inc
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) psyscall *.inc *.o

.PHONY: all clean
