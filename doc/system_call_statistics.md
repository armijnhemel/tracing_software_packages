# System call statistics

## Trace statistics

When building the Linux 6.11 kernel with the configuration file found in
[`data/kernel-config-6.11`](../data/kernel-config-6.11) on a recent Fedora 39 the
following system calls are used:

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
