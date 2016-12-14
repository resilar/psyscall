#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern long psyscall(pid_t pid, long number, ...);

struct entry { const char *name; long number; };
static struct entry syscalls[] = {
#include "syscalls.inc"
};
static struct entry constants[] = {
#include "constants.inc"
};

static int entry_cmp(const void *a, const void *b) {
    const struct entry *A = a, *B = b;
    return strcmp(A->name, B->name);
}

long find_syscall(char *name)
{
    char *end;
    long nr = strtol(name, &end, 0);
    if (*end != '\0') {
        struct entry key = { name, 0 };
        struct entry *hit = bsearch(&key, syscalls,
                sizeof(syscalls)/sizeof(struct entry),
                sizeof(struct entry), entry_cmp);
        return hit ? hit->number : -1;
    }
    return nr;
}

/**
 * C-style constant (e.g., '42', 'PROT_READ|PROT_WRITE', ...)
 */
int parse_constant(char *arg, long *out)
{
    char *end;

    if (*arg == '\0' || *arg == '|')
        return 0;

    if ((end = strchr(arg, '|'))) {
        *end = '\0';
        arg = parse_constant(arg, out) + end;
        *end = '|';
        return parse_constant(arg, out);
    }

    *out |= strtol(arg, &end, 0);
    if (*end) {
        struct entry *hit, key = { arg, 0 };
        hit = bsearch(&key, constants,
                sizeof(constants)/sizeof(struct entry),
                sizeof(struct entry), entry_cmp);
        if (!hit) return 0;
        *out |= hit->number;
    }

    return 1;
}

/**
 * There are less cumbersome methods to write remote process memory.
 * However, PTRACE_POKEDATA is the most portable, so we use it.
 */
static long ptrace_write(pid_t pid, void *addr, void *buf, long len)
{
    while (len > 0) {
        int i, j;
        if ((i = ((unsigned long)addr % sizeof(long))) || len < sizeof(long)) {
            union {
                long value;
                unsigned char buf[sizeof(long)];
            } data;
            data.value = ptrace(PTRACE_PEEKDATA, pid, (char *)addr - i, 0);
            for (j = i; j < sizeof(long) && j-i < len; j++) {
                data.buf[j] = ((char *)buf)[j-i];
            }
            ptrace(PTRACE_POKEDATA, pid, (char *)addr - i, data.value);
            addr = (char *)addr + (j-i);
            buf = (char *)buf + (j-i);
            len -= j-i;
        } else {
            j = len/sizeof(long);
            for (i = 0; i < j; i++) {
                ptrace(PTRACE_POKEDATA, pid, addr, *(long *)buf);
                addr = (char *)addr + sizeof(long);
                buf = (char *)buf + sizeof(long);
                len -= sizeof(long);
            }
        }
    }
    return 1;
}

int main(int argc, char *argv[])
{
    pid_t pid;
    int i, len;
    long number,  ret;
    unsigned long addr;
    long arg[6] = {0};

    if (argc < 3 || argc > 9) {
        fprintf(stderr, "syscall() inject0r\n");
        fprintf(stderr, "usage: %s pid syscall [arg0] ... [arg5]\n", argv[0]);
        return argc > 1;
    } else if (!(pid = atoi(argv[1])) || pid == getpid() || kill(pid, 0)) {
        fprintf(stderr, "bad pid: %s\n", argv[1]);
        return 2;
    } else if ((number = find_syscall(argv[2])) < 0) {
        fprintf(stderr, "bad syscall: %s\n", argv[2]);
        return 3;
    }

    /**
     * Parse arguments and count the total length of input strings.
     */
    len = 0;
    for (i = 3; i < argc; i++) {
        const char *p;
        if (argv[i][0] == '"' && (p = strchr(argv[i]+1, '"')) && !p[1]) {
            len += (p - argv[i]);
            continue;
        }
        if (!parse_constant(argv[i], &arg[i-3])) {
            fprintf(stderr, "bad arg%d: %s\n", i-3, argv[i]);
            return i+1;
        }
    }

    /**
     * Allocate a block of memory for string arguments.
     */
    addr = 0;
    if (len) {
        int status;
        long pagesz = sysconf(_SC_PAGE_SIZE);
        for (i = 0; i < 2; i++) {
            if ((ret = find_syscall(i ? "mmap" : "mmap2")) != -1) {
                ret = psyscall(pid, ret, NULL, (1 + len/pagesz) * pagesz,
                        PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                if (ret != -1) break;
            }
        }
        if (i == 2) {
            fprintf(stderr, "allocating memory from target failed\n");
            return 11;
        }
        addr = (unsigned long)ret;

        if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1) {
            fprintf(stderr, "ptrace() attach failed: %s\n", strerror(errno));
            return 12;
        }
        if (waitpid(pid, &status, 0) == -1 || !WIFSTOPPED(status)) {
            fprintf(stderr, "stopping target process failed\n");
            ptrace(PTRACE_DETACH, pid, NULL, 0);
            return 12;
        }

        len = 0;
        for (i = 3; i < argc; i++) {
            char *p;
            if (argv[i][0] == '"' && (p = strchr(argv[i]+1, '"')) && !p[1]) {
                *p = '\0';
                arg[i-3] = addr+len;
                ptrace_write(pid, (void *)(addr+len), argv[i]+1, p - argv[i]);
                len += (p - argv[i]);
                *p = '"';
            }
        }
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        len = (1 + len/pagesz) * pagesz;
    }

    /**
     * Finally, inject the syscall.
     */
    ret = psyscall(pid, number, arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
    if (addr) psyscall(pid, SYS_munmap, addr, len);

    fprintf(stdout, "[%d] syscall(%s", pid, argv[2]);
    for (i = 3; i < argc; i++) {
        fprintf(stdout, ", %s", arg[i-3] ? argv[i] : "0");
    }
    if (ret >= 0x1000){
        fprintf(stdout, ") = %ld (0x%08lX)\n", ret, ret);
    } else fprintf(stdout, ") = %ld\n", ret);
    return 0;
}
