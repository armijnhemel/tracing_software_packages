# System call statistics

## Linux kernel 6.11 on Fedora 39

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
  89718 pwrite64
      4 rename
     25 renameat2
      1 symlinkat
   2272 unlink
   2669 unlinkat
   4125 vfork
  37593 wait4
 526659 write
```

When building the Linux 6.11 kernel without filtering the following system
calls are used:

```console
  88156 access
  42154 arch_prctl
 237764 brk
   1779 chdir
     32 chmod
      2 clock_gettime
      4 clone3
2395030 close
     10 copy_file_range
    169 dup
  14325 dup2
      1 dup3
  32257 execve
      4 exit
  24791 exit_group
     70 faccessat2
    778 fadvise64
     17 fchdir
      1 fchmod
      5 fchmodat
 126192 fcntl
      5 fsetxattr
   1744 ftruncate
  10858 futex
  35277 getcwd
   5528 getdents64
  25171 getegid
  25207 geteuid
  25170 getgid
      8 getgroups
   4624 getpgrp
  29110 getpid
  13866 getppid
  21212 getrandom
   2085 getrusage
      1 gettid
  25170 getuid
  37740 ioctl
      6 lgetxattr
      6 listxattr
 672136 lseek
      4 madvise
   1904 mkdir
 565090 mmap
 106449 mprotect
     25 mremap
  37576 munmap
2599717 newfstatat
4104591 openat
   8962 pipe2
    203 poll
     48 prctl
 102869 pread64
  44750 prlimit64
  89718 pwrite64
3130646 read
 178483 readlink
      4 rename
     25 renameat2
  21081 rseq
 280740 rt_sigaction
 242538 rt_sigprocmask
  12799 rt_sigreturn
      2 sched_getaffinity
  36124 set_robust_list
  21077 set_tid_address
     71 sigaltstack
   3444 statfs
     10 statx
      1 symlinkat
  11025 sysinfo
   1318 umask
   4633 uname
   2272 unlink
   2669 unlinkat
      3 utimensat
   4125 vfork
  37593 wait4
 526659 write
```

When looking at the flags to `open` and `openat` it can be seen that there are
18 combinations of flags used:

```console
 1	1182683 ['O_RDONLY']
 2	1019255 ['O_RDONLY', 'O_NOCTTY']
 3	 119755 ['O_RDONLY', 'O_CLOEXEC']
 4	   8045 ['O_WRONLY', 'O_CREAT', 'O_TRUNC']
 5	   4621 ['O_RDWR', 'O_NONBLOCK']
 6	   4494 ['O_RDONLY', 'O_NONBLOCK', 'O_CLOEXEC', 'O_DIRECTORY']
 7	   2577 ['O_RDWR', 'O_CREAT', 'O_TRUNC']
 8	   2272 ['O_RDWR', 'O_CREAT', 'O_EXCL']
 9	   1816 ['O_WRONLY', 'O_CREAT', 'O_APPEND']
10	   1800 ['O_RDWR']
11	    166 ['O_WRONLY', 'O_TRUNC']
12	    142 ['O_RDONLY', 'O_NOCTTY', 'O_NONBLOCK', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_DIRECTORY']
13	      6 ['O_RDONLY', 'O_NOCTTY', 'O_NONBLOCK', 'O_NOFOLLOW', 'O_DIRECTORY']
14	      5 ['O_WRONLY', 'O_CREAT', 'O_EXCL']
15	      5 ['O_RDONLY', 'O_PATH', 'O_DIRECTORY']
16	      3 ['O_WRONLY', 'O_CREAT', 'O_NOCTTY', 'O_NONBLOCK']
17	      1 ['O_WRONLY', 'O_CREAT', 'O_TRUNC', 'O_CLOEXEC']
18	      1 ['O_WRONLY', 'O_CREAT', 'O_NONBLOCK']
```

## BusyBox 1.37 on Fedora 39

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
