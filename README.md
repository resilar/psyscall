Linux syscall() injection.

Tested on x86, ARMv7, MIPS, PPC64.


# Examples

**Inject exit(42)**
```
% sleep 60 &
[1] 123
% ./psyscall 123 exit 42
[123] syscall(exit, 42) = 42 (0x0000002A)
[1]  + exit 42    sleep 60
% wait 123; echo $?
42
```

**Redirect stderr to /tmp/stderr.log**
```
% pidof target
666
% touch /tmp/stderr.log
% ./psyscall 666 open '"/tmp/stderr.log"' O_RDWR
[666] syscall(open, "/tmp/stderr.log", O_RDWR) = 3
% ./psyscall `pidof target` dup2 3 2            
[666] syscall(dup2, 3, 2) = 2
```

**Write getcwd() to the redirected stderr**
```
% ./psyscall 666 mmap 0 0x1000 'PROT_READ|PROT_WRITE' 'MAP_PRIVATE|MAP_ANONYMOUS' -1 0
[666] syscall(mmap, 0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 140544083800064 (0x7fd2f830b000)
% ./psyscall 666 getcwd 0x7fd2f830b000 0x1000
[666] syscall(getcwd, 0x7fd2f830b000, 0x1000) = 24 (0x00000018)
% ./psyscall 666 write 2 0x7fd2f830b000 24   
[666] syscall(write, 2, 0x7fd2f830b000, 24) = 24 (0x00000018)
% cat /tmp/stderr.log                       
/home/resilar/psyscall-target
```
