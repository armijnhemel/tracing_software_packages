# Running strace

Let's take the Linux kernel as an example. First trace a Linux kernel build
with (for example) the following command, but make sure there is enough disk
space available, as trace files for the Linux kernel tend to get really big.
The assumption below is that PIDs do not wrap and are not reused. On older
Linux systems this is an issue, but on newer Linux systems this should not
be a problem. You can verify this by checking the maximum amount of PIDs used
on your system:

```console
$ cat /proc/sys/kernel/pid_max
4194304
```

The following command will write tracefiles for a subset of system calls, with
one trace file per process:

```console
$ strace -o ../trace/linux-strace -e trace=chdir,getcwd,link,linkat,mkdir,newfstatat,open,openat,rename,renameat2,sendfile,symlink,symlinkat,unlink,unlinkat,%process,dup,dup2,dup3,close,pipe,tee,fchdir -y -Y -qq -ttt -f -ff --seccomp-bpf -s 256 make
```

This will write the individual trace files to a directory
(`../trace/linux-strace`) which can then be processed.

## Statistics

Tracing a build of the Linux kernel creates many files, and the trace files
take quite a bit of space as well:

```console
$ cd ../trace/linux-strace
$ ls | wc -l
24795
$ du -h
1.4G	.
```