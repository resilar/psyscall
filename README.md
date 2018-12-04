# psyscall

Linux syscall() injection to external processes.

Tested on x86 (Arch Linux & Ubuntu), ARMv7 (Android 6 & 7), MIPS (Debian), PPC64 (Debian).

Requires `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` (or root privileges).

## Examples

**Kill emacs as vim**
```
% ./psyscall `pidof vim` kill `pidof emacs` SIGTERM
[88] syscall(kill, 142, SIGTERM) = 0
```
j/k i don't have `emacs` installed.

**Drop root privileges**
```
% pidof wireshark
609
% sudo ./psyscall 609 getuid
[sudo] password for resilar:
[609] syscall(getuid) = 0
% sudo ./psyscall 609 setuid 1000
[609] syscall(setuid, 1000) = 0
% sudo ./psyscall 609 getuid
[609] syscall(getuid) = 1000
```

**Make `sleep` speak and exit with the code 42**
```
% sleep 60 &
[1] 123
% ./psyscall 123 write 1 \"foobar\" 6
foobar[123] syscall(write, 1, "foobar", 6) = 6
% ./psyscall 123 exit 42
[123] syscall(exit, 42) = 42
[1]  + exit 42    sleep 60
% wait 123; echo $?
42
```

**Redirect stderr to /tmp/stderr.log and write getcwd() to it**
```
% touch /tmp/stderr.log
% ./psyscall 666 open '"/tmp/stderr.log"' O_RDWR
[666] syscall(open, "/tmp/stderr.log", O_RDWR) = 3
% ./psyscall 666 dup2 3 2
[666] syscall(dup2, 3, 2) = 2
% ./psyscall 666 mmap 0 0x1000 'PROT_READ|PROT_WRITE' 'MAP_PRIVATE|MAP_ANONYMOUS' -1 0
[666] syscall(mmap, 0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fd2f830b000
% ./psyscall 666 getcwd 0x7fd2f830b000 0x1000
[666] syscall(getcwd, 0x7fd2f830b000, 0x1000) = 24
% ./psyscall 666 write 2 0x7fd2f830b000 24
[666] syscall(write, 2, 0x7fd2f830b000, 24) = 24
% cat /tmp/stderr.log
/home/resilar/psyscall-target
```
