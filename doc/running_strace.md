# Running strace

Let's take the Linux kernel as an example. First trace a Linux kernel build
with (for example) the following command, but make sure there is enough disk
space available, as trace files for the Linux kernel tend to get really big.
The assumption made in this project is that PIDs do not wrap and are not
reused. On older Linux systems this can be an issue, but on newer Linux systems
this should not be a problem. You can verify this by checking the maximum
amount of PIDs used on your system:

```console
$ cat /proc/sys/kernel/pid_max
4194304
```

If it is large enough (like the above), then the change of PIDs wrapping is
very low, unless there are very long running builds using more than this number
of processes. In that case the PID will wrap and the strace processing scripts
will fail.

The following command will write tracefiles for a subset of system calls, with
one trace file per process:

```console
$ strace -o ../trace/linux-strace -e trace=chdir,getcwd,link,linkat,mkdir,newfstatat,open,openat,rename,renameat2,copy_file_range,sendfile,sendfile64,symlink,symlinkat,unlink,unlinkat,%process,dup,dup2,dup3,close,pipe,pipe2,tee,fchdir -y -Y -qq -ttt -f -ff --seccomp-bpf -s 256 make
```

This will write the individual trace files to a directory
(`../trace/linux-strace`) which can then be processed.

Compared to a "full" invocation this leaves out the following syscalls from
`%file`:

* `access`
* `chmod`
* `faccessat2`
* `fchmodat`
* `readlink` (TODO: put this one back in?)
* `statfs`
* `utimensat`

The following syscalls (from `%file`) can possibly be ignored, but this needs
more research:

* `mkdir`
* `unlink`
* `unlinkat`

TODO: There are probably more calls that need to be added
* `fcntl`

TODO: what to do with writes to files? There are sometimes zero sized files
that are merely touched, but no content is written to them. Should write
calls such as `write()` also be tracked?


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
