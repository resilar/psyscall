#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define PT_REGS (sizeof(((struct user *)0)->regs)/sizeof(unsigned long))

static struct {
    enum reg_type {
        ARCH_GP = 0,
        ARCH_PC,
        ARCH_SP,
        ARCH_RET
    } regs[PT_REGS];
    int pc, sp, ret;
} arch;

static long stub1(long number) { return kill(number, SIGSTOP); }
static int stub0(void *x)
{
    int pid = getpid();
    ptrace(PTRACE_TRACEME);
    syscall(SYS_kill, pid, SIGSTOP);
    syscall(SYS_getpid, 0, &pid, &x);
    syscall(SYS_getppid, 0, 1, 2, 3, 4, 5);
    x = (void *)((long (*)(long))((~(unsigned long)stub1 & ~0x3) | 2))(pid);
    return !x;
}

static int init_arch()
{
    pid_t child, parent;
    int status, crash, i;
    unsigned long stack, pagesz;
    long regs0[PT_REGS], regs[PT_REGS];

    arch.sp = arch.pc = arch.ret = -1;
    memset(arch.regs, 0, sizeof(arch.regs));

    /**
     * Allocate a stack for a clone.
     */
    pagesz = getpagesize();
    stack = (unsigned long)mmap(NULL, pagesz, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) + pagesz;
    child = clone(stub0, (void *)stack, SIGCHLD, NULL);
    if (child == -1) {
        fprintf(stderr, "clone(): %s\n", strerror(errno));
        munmap((void *)(stack-pagesz), pagesz);
        return 0;
    }
    parent = getpid();
    waitpid(child, &status, 0);
    if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)) {
        fprintf(stderr, "failed to stop a clone\n");
        goto die;
    }

    /**
     * Mark SP register(s).
     */
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
        fprintf(stderr, "ptrace(PTRACE_GETREGS): %s\n", strerror(errno));
        goto die;
    }
    for (i = 0; i < PT_REGS; i++) {
        if (regs[i] <= stack && stack <= regs[i]+0x80) {
            arch.regs[i] = ARCH_SP;
        }
    }

    /**
     * Get registers after getpid() and getppid() syscalls.
     */
    if (ptrace(PTRACE_SYSCALL, child, NULL, 0) == -1) {
        fprintf(stderr, "ptrace(PTRACE_SYSCALL): %s\n", strerror(errno));
        goto die;
    }
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && (WSTOPSIG(status) & ~0x80) == SIGTRAP) {
        ptrace(PTRACE_SYSCALL, child, NULL, 0);
        waitpid(child, &status, 0);
    }
    ptrace(PTRACE_GETREGS, child, NULL, &regs0);
    ptrace(PTRACE_SYSCALL, child, NULL, 0);
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && (WSTOPSIG(status) & ~0x80) == SIGTRAP) {
        ptrace(PTRACE_SYSCALL, child, NULL, 0);
        waitpid(child, &status, 0);
    }
    ptrace(PTRACE_GETREGS, child, NULL, &regs);

    /**
     * RET & SP registers.
     */
    for (i = 0; i < PT_REGS; i++) {
        if (arch.regs[i] == ARCH_SP) {
            if (regs[i] <= stack && stack <= regs[i]+0x80) {
                if (arch.sp < 0 || regs0[i] < regs0[arch.sp])
                    arch.sp = i;
                arch.regs[i] = ARCH_SP;
                continue;
            }
            arch.regs[i] = 0;
        }
        if (regs0[i] == child && regs[i] == parent) {
            arch.regs[i] = ARCH_RET;
            if (arch.ret >= 0) {
                fprintf(stderr, "warning: ambiguous RET register\n");
                continue;
            }
            arch.ret = i;
        }
    }

    /**
     * PC register.
     */
    i = 0;
    ptrace(PTRACE_CONT, child, NULL, 0);
    waitpid(child, &status, 0);
    crash = WSTOPSIG(status);
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    while (WIFSTOPPED(status) && WSTOPSIG(status) == crash && i < PT_REGS) {
        if ((regs[i] & ~0x3) == (~(unsigned long)stub1 & ~0x3)) {
            memcpy(regs0, regs, sizeof(regs));
            regs0[i] = (unsigned long)stub1;
            ptrace(PTRACE_SETREGS, child, NULL, regs0);
            ptrace(PTRACE_CONT, child, NULL, 0);
            waitpid(child, &status, 0);
            if (WIFSTOPPED(status) && WSTOPSIG(status) != crash) {
                arch.regs[arch.pc = i] = ARCH_PC;
                break;
            }
            ptrace(PTRACE_SETREGS, child, NULL, regs);
        }
        i++;
    }

    if (arch.pc < 0) fprintf(stderr, "PC register missing\n");
    if (arch.sp < 0) fprintf(stderr, "SP register missing\n");
    if (arch.ret < 0) fprintf(stderr, "RET register missing\n");

die:
    kill(child, SIGKILL);
    munmap((void *)(stack-pagesz), pagesz);
    return arch.sp >= 0 && arch.pc >= 0 && arch.ret >= 0;
}

/**
 * /proc/pid/maps format:
 * address           perms offset  dev   inode   pathname
 * 00400000-00580000 r-xp 00000000 fe:01 4858009 /usr/lib/nethack/nethack
 */
struct proc_map {
    void *start, *end;
    char perms[4];
    char path[PATH_MAX];
};

static FILE *proc_maps_open(pid_t pid)
{
    if (pid) {
        char filename[32];
        sprintf(filename, "/proc/%d/maps", (int)pid);
        return fopen(filename, "r");
    }
    return fopen("/proc/self/maps", "r");
}

static FILE *proc_maps_iter(FILE *it, struct proc_map *map)
{
    if (it) {
        if (fscanf(it, "%p-%p %c%c%c%c %*[^ ] %*[^ ] %*[^ ]%*[ ]%[^\n]",
                &map->start, &map->end, &map->perms[0], &map->perms[1],
                &map->perms[2], &map->perms[3], map->path) >= 6) {
            return it;
        }
        fclose(it);
    }
    memset(map, 0, sizeof(struct proc_map));
    return 0;
}

static int proc_maps_find(pid_t pid, void *addr, char *path,
        struct proc_map *out)
{
    FILE *it = proc_maps_open(pid);
    while ((it = proc_maps_iter(it, out))) {
        if (path && strcmp(out->path, path) != 0)
            continue;
        if (addr && !(out->start <= addr && addr < out->end))
            continue;
        fclose(it);
        return 1;
    }
    return 0;
}

long psyscall(pid_t pid, long number, ...)
{
    va_list ap;
    FILE *it;
    pid_t child;
    int i, status;
    void *stack_va;
    struct proc_map libc, map;
    unsigned long syscall_sym_rva;
    long argv[6], regs[PT_REGS], saved[PT_REGS], ret;
    static int initialized = 0;

    if (kill(pid, 0)) {
        fprintf(stderr, "invalid process (pid=%d): %s\n", pid, strerror(errno));
        return -1;
    }
    if (!initialized && !(initialized = init_arch())) {
        errno = EFAULT;
        return -1;
    }

    /**
     * Find a matching version of libc in the target and current process.
     * Note that we do not actually need matching versions, but the check helps
     * to prevent injection to incompatible processes (e.g., between 32-bit and
     * 64-bit processes).
     */
    it = proc_maps_open(pid);
    while ((it = proc_maps_iter(it, &libc))) {
        char *file = strrchr(libc.path, '/');
        if ((file = strstr(file ? file + 1 : libc.path, "libc"))
                && !strcmp(&file[strspn(file+4, "0123456789-.")+4], "so")
                && proc_maps_find(0, 0, libc.path, &map)) {
            void *handle, *addr;
            if ((handle = dlopen(libc.path, RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL))
                    && (addr = dlsym(handle, "syscall"))) {
                syscall_sym_rva = (long)addr - (long)map.start;
                dlclose(handle);
                fclose(it);
                break;
            }
            if (handle) dlclose(handle);
        }
    }
    if (it == NULL) {
        fprintf(stderr, "/proc/{self,%d}/maps have incompatible libc\n", pid);
        errno = EINVAL;
        return -1;
    }

    /**
     * Capture (local) syscall context from a forked child process.
     */
    va_start(ap, number);
    for (i = 0; i < 6; argv[i++] = va_arg(ap, long))
    va_end(ap);
    if (!(child = fork())) {
        if (ptrace(PTRACE_TRACEME) != -1 && !kill(getpid(), SIGSTOP)) {
            ((long (*)(long, ...))((~(unsigned long)psyscall & ~0x3) | 0x2))
                (number, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
        }
        exit(0);
    } else if (child == -1) {
        fprintf(stderr, "fork(): %s\n", strerror(errno));
        return -1;
    }
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        ptrace(PTRACE_CONT, child, NULL, 0);
        waitpid(child, &status, 0);
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "failed to stop a fork\n");
        kill(child, SIGKILL);
        errno = ECHILD;
        return -1;
    }
    ptrace(PTRACE_GETREGS, child, NULL, &regs);

    /**
     * Stop the target process.
     */
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) == -1) {
        fprintf(stderr, "ptrace(PTRACE_ATTACH): %s\n", strerror(errno));
        kill(child, SIGKILL);
        return -1;
    }
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "failed to stop the target pid=%d\n", pid);
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        kill(child, SIGKILL);
        errno = ECHILD;
        return -1;
    }
    ptrace(PTRACE_GETREGS, pid, NULL, &saved);

    /**
     * Prepare registers and stack.
     * TODO: This fails spectacularly if we have less than 0x10 longs of free
     *       space (per SP register) available in the bottom of the stack.
     */
    regs[arch.pc] =  (unsigned long)libc.start + syscall_sym_rva;
    if (!proc_maps_find(pid, 0, "[stack]", &map)) {
        fprintf(stderr, "/proc/%d/maps does not contain [stack] region\n", pid);
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        kill(child, SIGKILL);
        errno = ECHILD;
        return -1;
    }
    stack_va = (char *)map.start + 0x80;
    for (i = 0; i < PT_REGS; i++) {
        int j;
        if (arch.regs[i] != ARCH_SP)
            continue;
        if (!proc_maps_find(child, (void *)regs[i], NULL, &map))
            continue;
        if (map.perms[0] != 'r' || map.perms[1] != 'w')
            continue;

        for (j = 0; j < 0x10; j++) {
            long x = ptrace(PTRACE_PEEKDATA, child, (long *)regs[i]+j, 0);
            ptrace(PTRACE_POKEDATA, pid, (long *)stack_va+j, x);
        }
        regs[i] = (long)stack_va;
        stack_va = (long *)stack_va+j;
    }
    kill(child, SIGKILL);

    /**
     * Execute syscall.
     */
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status) && (WSTOPSIG(status) & ~0x80) == SIGTRAP) {
        ptrace(PTRACE_SYSCALL, pid, NULL, 0);
        waitpid(pid, &status, 0);
    }
    if (WIFSTOPPED(status)) {
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        ret = regs[arch.ret];
    } else if (WIFEXITED(status)) {
        errno = ESRCH;
        return WEXITSTATUS(status);
    } else {
        fprintf(stderr, "failed to invoke syscall()\n");
        errno = ECHILD;
        ret = -1;
    }

    /**
     * Clean up.
     */
    ptrace(PTRACE_SETREGS, pid, NULL, &saved);
    ptrace(PTRACE_DETACH, pid, NULL, 0);
    return ret;
}
