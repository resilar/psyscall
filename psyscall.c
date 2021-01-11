#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static void *pdlsym(pid_t pid, void *base, const char *symbol);

#define PT_REGS (sizeof(((struct user *)0)->regs)/sizeof(unsigned long))
static struct {
    enum reg_type {
        ARCH_GP  = 0x00,
        ARCH_PC  = 0x01,
        ARCH_SP  = 0x02,
        ARCH_RET = 0x04,
        ARCH_ARG = 0x08
    } regs[PT_REGS];
    int pc, sp, ret;
} arch;

static void *stub1(long number, ...) {
    syscall(SYS_kill, getpid(), SIGSTOP);
    syscall(SYS_getpid, number);
    return (void *)syscall(SYS_getppid, 0, 1, 2, 3, 4, 5);
}

static int stub0(void *x)
{
    volatile long pid = (long)getpid();
    ptrace(PTRACE_TRACEME);
    while (syscall(SYS_kill, pid, SIGSTOP, &pid) != 1337) {
        if (!x) {
            x = ((void *(*)(long, ...))((~(unsigned long)stub1 & ~0x3) | 2))
                (~(long)stub0, ~(long)stub0, ~(long)stub0,
                 ~(long)stub0, ~(long)stub0, ~(long)stub0);
        }
    }
    return pid && !x;
}

static int init_arch()
{
    pid_t child, parent;
    int status, i;
    unsigned long stack, pagesz;
    long regs0[PT_REGS], regs1[PT_REGS], regs[PT_REGS];

    arch.sp = arch.pc = arch.ret = -1;
    memset(arch.regs, 0, sizeof(arch.regs));

    /*
     * Allocate stack for child.
     */
    pagesz = sysconf(_SC_PAGE_SIZE);
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
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "failed to stop a clone\n");
        goto die;
    }
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs0) == -1) {
        fprintf(stderr, "ptrace(PTRACE_GETREGS): %s\n", strerror(errno));
        goto die;
    }

    /*
     * PC register.
     */
    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    for (i = 0; i < PT_REGS; i++) {
        if ((regs[i] & ~0x3) == (~(unsigned long)stub1 & ~0x3)) {
            unsigned long regsi = regs[i];
            regs[i] = (unsigned long)stub1;
            ptrace(PTRACE_SETREGS, child, NULL, regs);
            ptrace(PTRACE_CONT, child, NULL, NULL);
            waitpid(child, &status, 0);
            regs[i] = regsi;
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
                arch.regs[arch.pc = i] |= ARCH_PC;
                break;
            }
        }
    }

    /*
     * ARG registers.
     */
    for (i = 0; i < PT_REGS; i++) {
        if (regs[i] == ~(unsigned long)stub0)
            arch.regs[i] |= ARCH_ARG;
    }

    /*
     * Get registers after getpid() and getppid() syscalls.
     */
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
        fprintf(stderr, "ptrace(PTRACE_SYSCALL): %s\n", strerror(errno));
        goto die;
    }
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && (WSTOPSIG(status) & ~0x80) == SIGTRAP) {
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        waitpid(child, &status, 0);
    }
    ptrace(PTRACE_GETREGS, child, NULL, &regs1);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && (WSTOPSIG(status) & ~0x80) == SIGTRAP) {
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        waitpid(child, &status, 0);
    }
    ptrace(PTRACE_GETREGS, child, NULL, &regs);

    /*
     * Mark RET registers.
     */
    for (i = 0; i < PT_REGS; i++) {
        if (regs1[i] == child && regs[i] == parent)
            arch.regs[i] |= ARCH_RET;
    }

    /*
     * SP register.
     */
    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    for (i = 0; i < PT_REGS; i++) {
        if (regs0[i] <= stack && stack <= regs0[i] + 0x100) {
            if (regs1[i] <= stack && stack <= regs1[i] + pagesz) {
                if (regs0[i] == regs[i] && regs1[i] <= regs0[i]) {
                    if (arch.sp < 0 || regs1[i] < regs1[arch.sp])
                        arch.sp = i;
                    arch.regs[i] |= ARCH_SP;
                }
            }
        }
    }

    /*
     * RET registers.
     */
    for (i = 0; i < PT_REGS; i++) {
        if (arch.regs[i] & ARCH_RET) {
            unsigned long regsi = regs[i];
            regs[i] = 1337;
            ptrace(PTRACE_SETREGS, child, NULL, regs);
            ptrace(PTRACE_CONT, child, NULL, NULL);
            waitpid(child, &status, 0);
            regs[i] = regsi;

            if (WIFEXITED(status)) {
                child = -1;
                arch.ret = i;
                break;
            }
        }
    }

#if 0
    for (i = 0; i < PT_REGS; i++) {
        printf("regs[%02d] = 0x%016lX", i, regs[i]);
        if (arch.pc == i) printf(" *PC*");
        else if (arch.regs[i] & ARCH_PC) printf(" PC");
        if (arch.sp == i) printf(" *SP*");
        else if (arch.regs[i] & ARCH_SP) printf(" SP");
        if (arch.ret == i) printf(" *RET*");
        else if (arch.regs[i] & ARCH_RET) printf(" RET");
        if (arch.regs[i] & ARCH_ARG) printf(" ARG");
        printf("\n");
    }
#endif

    if (arch.pc < 0) fprintf(stderr, "PC register missing\n");
    if (arch.sp < 0) fprintf(stderr, "SP register missing\n");
    if (arch.ret < 0) fprintf(stderr, "RET register missing\n");

die:
    if (child >= 0)
        kill(child, SIGKILL);
    munmap((void *)(stack-pagesz), pagesz);
    return arch.sp >= 0 && arch.pc >= 0 && arch.ret >= 0;
}

/*
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
        sprintf(filename, "/proc/%ld/maps", (long)pid);
        return fopen(filename, "r");
    }
    return fopen("/proc/self/maps", "r");
}

static FILE *proc_maps_iter(FILE *it, struct proc_map *map)
{
    if (it) {
        map->path[0] = '\0';
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
    unsigned long syscall_va;
    long argv[6], regs[PT_REGS], saved[PT_REGS], ret;
    static int initialized = 0;
    if (!initialized && !(initialized = init_arch())) {
        errno = EFAULT;
        return -1;
    }

    /*
     * Stop the target process.
     */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "ptrace(PTRACE_ATTACH): %s\n", strerror(errno));
        return -1;
    }
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "failed to stop target pid=%d\n", (int)pid);
        errno = ECHILD;
        return -1;
    }

    /*
     * Find the virtual address of syscall() in the target process.
     */
    it = proc_maps_open(pid);
    while ((it = proc_maps_iter(it, &libc))) {
        char *file = strrchr(libc.path, '/');
        if ((file = strstr(file ? file + 1 : libc.path, "libc"))
                && !strcmp(&file[strspn(file+4, "0123456789-.")+4], "so")) {
            syscall_va = (unsigned long)pdlsym(pid, libc.start, "syscall");
            if (syscall_va) {
                fclose(it);
                break;
            }
        }
    }
    if (it == NULL || !proc_maps_find(pid, 0, "[stack]", &map)) {
        const char *fmt = it ? "stack of pid=%d missing\n"
                             : "libc of pid=%d not found\n"
                               "perhaps the target is statically linked?\n";
        fprintf(stderr, fmt, (int)pid);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        errno = EINVAL;
        return -1;
    }
    stack_va = (char *)map.start + 0x80;

    /*
     * Capture (local) syscall context from a fork.
     */
    va_start(ap, number);
    for (i = 0; i < 6; argv[i++] = va_arg(ap, long));
    va_end(ap);
    if (!(child = fork())) {
        if (ptrace(PTRACE_TRACEME) != -1 && !kill(getpid(), SIGSTOP)) {
            ((long (*)(long, ...))((~(unsigned long)psyscall & ~0x3) | 0x2))
                (number, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
        }
        exit(0);
    } else if (child == -1) {
        fprintf(stderr, "fork(): %s\n", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        ptrace(PTRACE_CONT, child, NULL, NULL);
        waitpid(child, &status, 0);
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "failed to stop fork\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        kill(child, SIGKILL);
        errno = ECHILD;
        return -1;
    }
    ptrace(PTRACE_GETREGS, child, NULL, &regs);

    /*
     * Prepare registers and stack.
     * TODO: This fails spectacularly if we have less than 0x10 longs of free
     *       space (per SP register) available in the bottom of the stack.
     */
    ptrace(PTRACE_GETREGS, pid, NULL, &saved);
    regs[arch.pc] = syscall_va;
    for (i = 0; i < PT_REGS; i++) {
        if (!arch.regs[i]) {
            regs[i] = saved[i];
        } else if (arch.regs[i] & ARCH_SP) {
            int j;
            if (!proc_maps_find(child, (void *)regs[i], NULL, &map))
                continue;
            if (map.perms[0] != 'r' || map.perms[1] != 'w')
                continue;

            for (j = 0; j < 0x10; j++) {
                ptrace(PTRACE_POKEDATA, pid, (long *)stack_va+j,
                       ptrace(PTRACE_PEEKDATA, child, (long *)regs[i]+j, NULL));
            }
            regs[i] = (long)stack_va;
            stack_va = (long *)stack_va+j;
        }
    }
    kill(child, SIGKILL);

    /*
     * Execute syscall() in the target process.
     */
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status) && (WSTOPSIG(status) & ~0x80) == SIGTRAP) {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
    }
    if (WIFEXITED(status)) {
        fprintf(stderr, "target pid=%d exited unexpectedly", (int)pid);
        errno = ESRCH;
        return WEXITSTATUS(status);
    }

    /*
     * Get result and detach from the target.
     */
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    ptrace(PTRACE_SETREGS, pid, NULL, &saved);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (WIFSTOPPED(status)) {
        ret = regs[arch.ret];
    } else {
        fprintf(stderr, "failed to execute injected syscall\n");
        errno = ECHILD;
        ret = -1;
    }

    return ret;
}

/*
 * The rest of this file contains pdlsym() implementation for ELF systems.
 */

struct elf {
    pid_t pid;
    uintptr_t base;
    uint8_t class, data;
    uint16_t type;
    int W;

    int (*getN)(pid_t pid, const void *addr, void *buf, size_t len);

    struct {
        uintptr_t offset;
        uint16_t size, num;
    } phdr;

    uintptr_t symtab, syment;
    uintptr_t strtab, strsz;
};

static int readN(pid_t pid, const void *addr, void *buf, size_t len)
{
    int errnold = errno;
    if (!pid) {
        memmove(buf, addr, len);
        return 1;
    }

    errno = 0;
    while (!errno && len > 0) {
        size_t i, j;
        if ((i = ((size_t)addr % sizeof(long))) || len < sizeof(long)) {
            union {
                long value;
                char buf[sizeof(long)];
            } data;
            data.value = ptrace(PTRACE_PEEKDATA, pid, (char *)addr - i, NULL);
            if (!errno) {
                for (j = i; j < sizeof(long) && j-i < len; j++)
                    ((char *)buf)[j-i] = data.buf[j];
                addr = (char *)addr + (j-i);
                buf = (char *)buf + (j-i);
                len -= j-i;
            }
        } else {
            for (i = 0, j = len/sizeof(long); i < j; i++) {
                *(long *)buf = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
                if (errno) break;
                addr = (char *)addr + sizeof(long);
                buf = (char *)buf + sizeof(long);
                len -= sizeof(long);
            }
        }
    }
    if (!errno)
        errno = errnold;
    return !len;
}

static int Ndaer(pid_t pid, const void *addr, void *buf, size_t len)
{
    int ok = readN(pid, addr, buf, len);
    if (ok) {
        char *p, *q;
        for (p = buf, q = p + len-1; p < q; *p ^= *q, *q ^= *p, *p++ ^= *q--);
    }
    return ok;
}

static uint8_t get8(pid_t pid, const void *addr)
{
    uint8_t ret;
    return readN(pid, addr, &ret, sizeof(uint8_t)) ? ret : 0;
}
static uint16_t get16(struct elf *elf, const void *addr)
{
    uint16_t ret;
    return elf->getN(elf->pid, addr, &ret, sizeof(uint16_t)) ? ret : 0;
}
static uint32_t get32(struct elf *elf, const void *addr)
{
    uint32_t ret;
    return elf->getN(elf->pid, addr, &ret, sizeof(uint32_t)) ? ret : 0;
}
static uint64_t get64(struct elf *elf, const void *addr)
{
    uint64_t ret;
    return elf->getN(elf->pid, addr, &ret, sizeof(uint64_t)) ? ret : 0;
}

static uintptr_t getW(struct elf *elf, const void *addr)
{
    return (elf->class == 0x01) ? (uintptr_t)get32(elf, addr)
                                : (uintptr_t)get64(elf, addr);
}

static int loadelf(pid_t pid, const void *addr, struct elf *elf)
{
    uint32_t magic;
    int i, j, loads;
    const char *base = addr;

    /*
     * ELF header.
     */
    elf->pid = pid;
    elf->base = (uintptr_t)base;
    if (readN(pid, base, &magic, 4) && !memcmp(&magic, "\x7F" "ELF", 4)
            && ((elf->class = get8(pid, base+4)) == 1 || elf->class == 2)
            && ((elf->data = get8(pid, base+5)) == 1 || elf->data == 2)
            && get8(pid, base+6) == 1) {
        union { uint16_t value; char buf[2]; } data;
        data.value = (uint16_t)0x1122;
        elf->getN = (data.buf[0] & elf->data) ? Ndaer : readN;
        elf->type = get16(elf, base + 0x10);
        elf->W = (2 << elf->class);
    } else {
        /* Bad ELF */
        return 0;
    }

    /*
     * Program headers.
     */
    loads = 0;
    elf->strtab = elf->strsz = elf->symtab = elf->syment = 0;
    elf->phdr.offset = getW(elf, base + 0x18 + elf->W);
    elf->phdr.size = get16(elf, base + 0x18 + elf->W*3 + 0x6);
    elf->phdr.num = get16(elf, base + 0x18 + elf->W*3 + 0x8);
    for (i = 0; i < elf->phdr.num; i++) {
        uint32_t phtype;
        uintptr_t offset, vaddr, filesz, memsz;
        const char *ph = base + elf->phdr.offset + i*elf->phdr.size;

        phtype = get32(elf, ph);
        if (phtype == 0 /* PT_NULL */)
            break;
        if (phtype != 1 /* PT_LOAD */ && phtype != 2 /* PT_DYNAMIC */)
            continue;

        offset = getW(elf, ph + elf->W);
        vaddr  = getW(elf, ph + elf->W*2);
        filesz = getW(elf, ph + elf->W*4);
        memsz  = getW(elf, ph + elf->W*5);
        if (vaddr < offset || memsz < filesz)
            return 0;

        if (phtype == 1) { /* PT_LOAD */
            if (elf->type == 2) { /* ET_EXEC */
                if (vaddr - offset < elf->base) {
                    /* This is not the lowest base of the ELF */
                    errno = EFAULT;
                    return 0;
                }
            }
            loads++;
        } else if (phtype == 2) { /* PT_DYNAMIC */
            const char *tag;
            uintptr_t type, value;
            tag = (char *)((elf->type == 2) ? 0 : base) + vaddr;
            for (j = 0; 2*j*elf->W < memsz; j++) {
                if ((type = getW(elf, tag + 2*elf->W*j))) {
                    value = getW(elf, tag + 2*elf->W*j + elf->W);
                    switch (type) {
                    case 5: elf->strtab = value; break; /* DT_STRTAB */
                    case 6: elf->symtab = value; break; /* DT_SYMTAB */
                    case 10: elf->strsz = value; break; /* DT_STRSZ */
                    case 11: elf->syment = value; break; /* DT_SYMENT */
                    default: break;
                    }
                } else {
                    /* DT_NULL */
                    break;
                }
            }
        }
    }

    /* Check that we have all program headers required for dynamic linking */
    if (!loads || !elf->strtab || !elf->strsz || !elf->symtab || !elf->syment)
        return 0;

    /* String table (immediately) follows the symbol table */
    if (!(elf->symtab < elf->strtab))
        return 0;

    /* Symbol entry size is a non-zero integer that divides symtab size */
    if ((elf->strtab - elf->symtab) % elf->syment)
        return 0;

    /* All OK! */
    return 1;
}

static int sym_iter(struct elf *elf, int i, uint32_t *stridx, uintptr_t *value)
{
    if (i*elf->syment < elf->strtab - elf->symtab) {
        const char *sym = (char *)elf->symtab + i*elf->syment;
        if (elf->symtab < elf->base)
            sym += elf->base;
        if ((*stridx = get32(elf, sym)) < elf->strsz) {
            if ((*value = getW(elf, sym + elf->W)) && elf->type != 2)
                *value += elf->base;
            return 1;
        }
    }
    return 0;
}

static void *pdlsym(pid_t pid, void *base, const char *symbol)
{
    struct elf elf;
    uintptr_t value = 0;
    if (loadelf((pid == getpid()) ? 0 : pid, base, &elf)) {
        int i;
        uint32_t stridx;
        const char *pstrtab;
        size_t size = strlen(symbol) + 1;
        if (size == 0)
            return NULL;
        pstrtab = (char *)elf.strtab + (elf.strtab < elf.base ? elf.base : 0);
        for (i = 0; sym_iter(&elf, i, &stridx, &value); value = 0, i++) {
            if (value && stridx+size <= elf.strsz) {
                size_t j = 0;
                while (j < size) {
                    char buf[sizeof(long)];
                    int n = ((uintptr_t)pstrtab + stridx+j) % sizeof(buf);
                    n = (size-j < sizeof(buf)) ? size-j : sizeof(buf) - n;
                    if (!readN(elf.pid, pstrtab + stridx+j, &buf, n))
                        break;
                    if (memcmp(&symbol[j], &buf, n))
                        break;
                    j += n;
                }
                if (j == size)
                    break;
            }
        }
    }
    return (void *)value;
}
