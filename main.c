#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
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

long parse_syscall(char *string)
{
    char *end;
    long nr = strtol(string, &end, 0);
    if (*end != '\0') {
        struct entry key = { string, 0 };
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
int parse_arg(char *arg, long *out)
{
    char *end;

    if (!arg || *arg == '\0' || *arg == '|')
        return 0;

    if ((end = strchr(arg, '|'))) {
        *end = '\0';
        arg = parse_arg(arg, out) ? end + 1 : 0;
        *end = '|';
        return parse_arg(arg, out);
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
    } else if (!(number = parse_syscall(argv[2]))) {
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
            len += (long)(p - argv[i]);
            continue;
        }
        if (!parse_arg(argv[i], &arg[i-3])) {
            fprintf(stderr, "bad arg%d: %s\n", i-3, argv[i]);
            return i+1;
        }
    }

    /**
     * Allocate a block of memory for string arguments.
     */
    addr = 0;
    if (len) {
        int fd;
        char path[32];
        long nr_mmap;
        long pagesz = sysconf(_SC_PAGE_SIZE);
        nr_mmap = parse_syscall("mmap");
        if (nr_mmap < 0) nr_mmap = parse_syscall("mmap2");
        ret = psyscall(pid, nr_mmap, NULL, (1 + len/pagesz) * pagesz,
                PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (ret == -1) {
            fprintf(stderr, "psyscall(%d, mmap, ...) failed\n", (int)pid);
            return 0;
        }
        addr = (unsigned long)ret;
        /* TODO: /proc/<pid>/mem doesn't work on PPC64, use ptrace instead. */
        sprintf(path, "/proc/%d/mem", (int)pid);
        if ((fd = open(path, O_RDWR)) < 0 || lseek(fd, addr, SEEK_SET) < 0) {
            fprintf(stderr, "open(%s) failed\n", path);
            return 0;
        }
        for (i = 3; i < argc; i++) {
            char *p;
            len = 0;
            if (argv[i][0] == '"' && (p = strchr(argv[i]+1, '"')) && !p[1]) {
                *p = '\0';
                arg[i-3] = addr+len;
                write(fd, argv[i]+1, (long)(p - argv[i]));
                len += (long)(p - argv[i]);
                *p = '"';
            }
        }
        len = (1 + len/pagesz) * pagesz;
        close(fd);
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
    if (ret >= 0x0A){
        fprintf(stdout, ") = %ld (0x%08lX)\n", ret, ret);
    } else fprintf(stdout, ") = %ld\n", ret);
    return 0;
}
