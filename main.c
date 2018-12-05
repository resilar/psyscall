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

static long find_syscall(char *name)
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

/*
 * Parses C-style constant (e.g., '42', 'PROT_READ|PROT_WRITE', ...)
 */
long parse_constant(char *arg, int *err)
{
    char *end;
    long value;

    if (*arg == '\0' || *arg == '|' || *arg == '+') {
        *err |= !!*arg;
        return 0;
    }

    if ((end = arg + strcspn(arg, "+|")) && *end) {
        char op = *end;
        *end = '\0';
        value = parse_constant(arg, err);
        *end++ = op;
        switch (op) {
        case '+': value += parse_constant(end, err); break;
        case '|': value |= parse_constant(end, err); break;
        default: *err |= 1; break;
        }
        return value;
    }

    value = strtol(arg, &end, 0);
    if (*end) {
        if (end == arg) {
            struct entry *hit, key = { arg, 0 };
            hit = bsearch(&key, constants,
                    sizeof(constants)/sizeof(struct entry),
                    sizeof(struct entry), entry_cmp);
            if (hit) {
                value = hit->number;
            } else {
                *err |= 1;
            }
        } else {
            *err |= 1;
        }
    }

    return value;
}

/*
 * There are more efficient and easier methods to write remote process memory.
 * However, PTRACE_POKEDATA is the most portable, so we use it.
 */
static long ptrace_write(pid_t pid, void *addr, void *buf, long len)
{
    long n = len;
    errno = 0;
    while (len > 0) {
        int i, j;
        if ((i = ((unsigned long)addr % sizeof(long))) || len < sizeof(long)) {
            union {
                long value;
                unsigned char buf[sizeof(long)];
            } data;
            data.value = ptrace(PTRACE_PEEKDATA, pid, (char *)addr-i, 0);
            if (errno) break;
            for (j = i; j < sizeof(long) && j-i < len; j++) {
                data.buf[j] = ((char *)buf)[j-i];
            }
            if (!ptrace(PTRACE_POKEDATA, pid, (char *)addr-i, data.value)) {
                addr = (char *)addr + (j-i);
                buf = (char *)buf + (j-i);
                len -= j-i;
            }
        } else {
            for (i = 0, j = len/sizeof(long); i < j; i++) {
                if (ptrace(PTRACE_POKEDATA, pid, addr, *(long *)buf) != 0)
                    return n - len;
                addr = (char *)addr + sizeof(long);
                buf = (char *)buf + sizeof(long);
                len -= sizeof(long);
            }
        }
    }
    return n - len;
}

int main(int argc, char *argv[])
{
    int i;
    pid_t pid;
    unsigned long addr, len;
    long ret, number, arg[6] = {0};

    errno = 0;
    if (argc < 3 || argc > 9) {
        fprintf(stderr, "syscall() inject0r\n");
        fprintf(stderr, "usage: %s pid syscall [arg0] ... [arg5]\n", argv[0]);
        return argc > 1;
    } else if (!(pid = atoi(argv[1])) || pid == getpid() || kill(pid, 0)) {
        if (errno)
            fprintf(stderr, "bad pid: %s (%s)\n", argv[1], strerror(errno));
        else fprintf(stderr, "bad pid: %s\n", argv[1]);
        return 2;
    } else if ((number = find_syscall(argv[2])) < 0) {
        fprintf(stderr, "bad syscall: %s\n", argv[2]);
        return 3;
    }

    /*
     * Parse arguments and count the total length of input strings.
     */
    len = 0;
    for (i = 3; i < argc; i++) {
        const char *p;
        int err = 0;
        if (argv[i][0] == '"' && (p = strchr(argv[i]+1, '"')) && !p[1]) {
            len += p-argv[i];
            continue;
        }
        arg[i-3] = parse_constant(argv[i], &err);
        if (err) {
            fprintf(stderr, "bad arg%d: %s\n", i-3, argv[i]);
            return 10+i;
        }
    }

    /*
     * Allocate a block of memory for string arguments.
     */
    addr = 0;
    if (len) {
        int status;
        long pagesz, sc;
        unsigned long j;
        if ((sc = find_syscall("mmap2")) == -1) {
            if ((sc = find_syscall("mmap")) == -1) {
                fprintf(stderr, "__NR_mmap missing\n");
                return 4;
            }
        }
        pagesz = sysconf(_SC_PAGE_SIZE);
        ret = psyscall(pid, sc, NULL, (len = pagesz * (1 + (len-1)/pagesz)),
                       PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (ret == (long)MAP_FAILED) {
            fprintf(stderr, "broken psyscall (or mmap failed) errno=%d (%s)\n",
                    errno, strerror(errno));
            return 5;
        }
        addr = (unsigned long)ret;

        if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1) {
            fprintf(stderr, "ptrace() attach failed: %s\n", strerror(errno));
            psyscall(pid, SYS_munmap, addr, len);
            return 6;
        }
        if (waitpid(pid, &status, 0) == -1 || !WIFSTOPPED(status)) {
            fprintf(stderr, "stopping target process failed\n");
            ptrace(PTRACE_DETACH, pid, NULL, 0);
            psyscall(pid, SYS_munmap, addr, len);
            return 7;
        }

        for (i = 3, j = 0; i < argc; i++) {
            char *p;
            if (argv[i][0] == '"' && (p = strchr(argv[i]+1, '"')) && !p[1]) {
                *p = '\0';
                ret = ptrace_write(pid, (char *)addr+j, argv[i]+1, p-argv[i]);
                *p = '"';
                if (ret == p-argv[i]) {
                    arg[i-3] = addr+j;
                    j += ret;
                } else {
                    fprintf(stderr, "ptrace_write() failed\n");
                    ptrace(PTRACE_DETACH, pid, NULL, 0);
                    psyscall(pid, SYS_munmap, addr, len);
                    return 8;
                }
            }
        }
        ptrace(PTRACE_DETACH, pid, NULL, 0);
    }

    /*
     * Finally, inject the syscall.
     */
    errno = 0;
    ret = psyscall(pid, number, arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
    if (len) psyscall(pid, SYS_munmap, addr, len);
    if (ret == -1) {
        fprintf(stderr, "[%d] psyscall() errno=%d (%s)\n",
                pid, errno, strerror(errno));
        return 9;
    }

    if (isatty(STDOUT_FILENO)) {
        fprintf(stdout, "[%d] syscall(%s", pid, argv[2]);
        for (i = 3; i < argc; i++) {
            fprintf(stdout, ", %s", arg[i-3] ? argv[i] : "0");
        }
        fprintf(stdout, ") = ");
    }
    fprintf(stdout, ((ret+!ret) & 0xFFF) ? "%ld\n" : "0x%08lx\n", ret);
    return 0;
}
