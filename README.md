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

### Tracing a build

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
$ strace -o ../trace/linux-strace -e trace=chdir,getcwd,link,linkat,mkdir,open,openat,rename,renameat2,sendfile,symlink,symlinkat,unlink,unlinkat,%process,dup,dup2,dup3,close,pipe,tee,fchdir -y -Y -qq -ttt -f -ff --seccomp-bpf -s 256 make
```

Compared to a "full" invocation this leaves out the following syscalls from
`%file`:

* `access`
* `chmod`
* `faccessat2`
* `fchmodat`
* `newfstatat`
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
* `sendfile64`

TODO: what to do with writes to files? There are sometimes zero sized files
that are merely touched, but no content is written to them. Should write
calls such as `write()` also be tracked?

## Funding

This project is funded through [NGI Zero Core](https://nlnet.nl/core), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program.
Learn more at the [NLnet project page](https://nlnet.nl/project/BuildTracing).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)


[TUD-SERG]:<https://web.archive.org/web/20130429174246/http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf>
[ASE-2014]:<https://rebels.cs.uwaterloo.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html>
