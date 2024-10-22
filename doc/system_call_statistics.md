# System call statistics

## Trace statistics

When building the Linux 6.11 kernel with the configuration file found in
[`data/kernel-6.11.config`](../data/kernel-6.11.config) on a recent Fedora 39 the
following system calls are used (with filtering):

```console
   1779 chdir
      4 clone3
2395030 close
    169 dup
  14325 dup2
      1 dup3
  32257 execve
      4 exit
  24791 exit_group
     17 fchdir
  35277 getcwd
   1904 mkdir
2599717 newfstatat
4104591 openat
      4 rename
     25 renameat2
      1 symlinkat
   2272 unlink
   2669 unlinkat
   4125 vfork
  37593 wait4
```

When building BusyBox 1.37 with the configuration found in
[`data/busybox-1.37.0.config`](../data/busybox-1.37.0.config) on a recent
Fedora 39 without filtering any system calls (so this is the full run) the
following system calls are used:

```console
  31065 access
  12200 arch_prctl
  39783 brk
     59 chdir
     15 chmod
      1 clock_nanosleep
 363165 close
     10 copy_file_range
   4563 dup
   2314 dup2
   9190 execve
   5668 exit_group
    119 faccessat2
    292 fadvise64
      3 fchdir
      1 fchmodat
  13193 fcntl
   9983 futex
   3419 getcwd
   5608 getdents64
   8203 getegid
   8859 geteuid
   8201 getgid
      6 getgroups
    993 getpgrp
   6235 getpid
   2977 getppid
   6137 getrandom
    644 getrusage
   8201 getuid
  10964 ioctl
 258144 lseek
    630 mkdir
 265542 mmap
  32458 mprotect
      2 mremap
 139191 munmap
 439542 newfstatat
 848634 openat
   1924 pipe2
      8 poll
      2 prctl
  12732 pread64
  13349 prlimit64
 415516 read
1847064 readlink
      8 rename
    645 renameat2
   6100 rseq
  48093 rt_sigaction
  39219 rt_sigprocmask
   3060 rt_sigreturn
      1 sched_getaffinity
   9348 set_robust_list
   6100 set_tid_address
    123 sigaltstack
   2252 statfs
   3122 sysinfo
    261 umask
   1000 uname
    779 unlink
    720 unlinkat
      1 utimensat
   1372 vfork
   8727 wait4
  64961 write
```
