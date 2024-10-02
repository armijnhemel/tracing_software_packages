# Tracing software package builds

This project aims to develop a standard for tracing (Linux) packages during
build time. This builds on research done in 2012 (published as a
[technical report][TUD-SERG]) and follow up research presented at the
[ASE 2014][ASE-2014] conference.

## How to use

There are two separate steps:

1. tracing the build using `strace`
2. processing the trace file

As an example, let's take the Linux kernel.

First trace a Linux kernel build with (for example) the following command, but
make sure there is enough disk space available, as trace files for the Linux
kernel tend to get really big.

```console
$ strace -o ../linux-strace -e trace=%file,%process,dup,dup2,dup3,close,pipe,tee,fchdir -y -Y -qq -f --seccomp-bpf -s 256 make
```

(TODO: is `close()` really needed?)

Alternatively, to save diskspace (recommended) for the trace file (sometimes up
to 50%), use:

```console
$ strace -o ../linux-strace -e trace=chdir,getcwd,link,linkat,mkdir,open,openat,rename,renameat2,sendfile,symlink,symlinkat,unlink,unlinkat,%process,dup,dup2,dup3,close,pipe,tee,fchdir -y -Y -qq -f --seccomp-bpf -s 256 make
```

The following syscalls (from `%file`) can be ignored:

* `access`
* `chmod`
* `faccessat2`
* `fchmodat`
* `newfstatat`
* `readlink`
* `statfs`
* `utimensat`

The following syscalls (from `%file`) can possibly be ignored:

* `mkdir`
* `unlink`
* `unlinkat`

TODO: There are probably more calls that need to be added
* `fcntl`
* `sendfile64`

TODO: what to do with writes to files? There are sometimes zero sized files
that are merely touched, but no content is written to them. Should write
calls such as `write()` also be tracked?



[TUD-SERG]:<https://web.archive.org/web/20130429174246/http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf>
[ASE-2014]:<https://rebels.cs.uwaterloo.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html>
