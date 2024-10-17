# Tracing software package builds

This project aims to develop a standard for tracing (Linux) packages during
build time. This builds on research done in 2012 (published as a
[technical report][TUD-SERG]) and follow up research presented at the
[ASE 2014][ASE-2014] conference.

This project has a few goals:

1. finding out which files were used to create specific binaries, enabling
   better search and allow creation of finer grained SBOM files
2. creating a reference dataset for many packages with this information

## How to use

There are two separate steps:

1. tracing the build using `strace`
2. processing the trace file

Let's take the Linux kernel as an example. First trace a Linux kernel build
with (for example) the following command, but make sure there is enough disk
space available, as trace files for the Linux kernel tend to get really big.

```console
$ strace -o ../trace/linux-strace -e trace=chdir,getcwd,link,linkat,mkdir,open,openat,rename,renameat2,sendfile,symlink,symlinkat,unlink,unlinkat,%process,dup,dup2,dup3,close,pipe,tee,fchdir -y -Y -qq -ttt -f -ff --seccomp-bpf -s 256 make
```

Compared to a "full" invocation this leaves out the following syscalls from
`%file`:

* `access`
* `chmod`
* `faccessat2`
* `fchmodat`
* `newfstatat`
* `readlink`
* `statfs`
* `utimensat`

The following syscalls (from `%file`) can possibly be ignored, but this needs
more research:

* `mkdir`
* `unlink`
* `unlinkat`

TODO: There are probably more calls that need to be added
* `fcntl`
* `sendfile64`

TODO: what to do with writes to files? There are sometimes zero sized files
that are merely touched, but no content is written to them. Should write
calls such as `write()` also be tracked?

## Statistics

When building the Linux 6.11 kernel with the configuration file found in
[`data/kernel-config-6.11`](data/kernel-config-6.11) on a recent Fedora 39 the
following system calls are used:

```console
   1779 chdir
  15043 clone
   5626 clone3
2395028 close
    169 dup
  14325 dup2
      1 dup3
  32257 execve
      4 exit
  24791 exit_group
     17 fchdir
  35277 getcwd
   1904 mkdir
4104589 openat
      4 rename
     25 renameat2
      1 symlinkat
   2272 unlink
   2669 unlinkat
   4125 vfork
  37593 wait4
```

[TUD-SERG]:<https://web.archive.org/web/20130429174246/http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf>
[ASE-2014]:<https://rebels.cs.uwaterloo.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html>
