# Tracing software package builds

This project aims to develop a standard for tracing (Linux) packages during
build time. This builds on research done in 2012 (published as a
[technical report][TUD-SERG]) and follow up research presented at the
[ASE 2014][ASE-2014] conference.

This project has a few goals:

1. finding out which files were used to create specific binaries, enabling
   better search and allow creation of finer grained SBOM files
2. creating a reference dataset for many packages with this information

## Quick start

Example: BusyBox 1.37.0

1. download BusyBox 1.37.0 sources: `wget -c https://busybox.net/downloads/busybox-1.37.0.tar.bz2`
1. unpack BusyBox 1.37.0 sources: `tar xf busybox-1.37.0.tar.bz2`
1. change to BusyBox directory: `cd busybox-1.37.0/`
1. copy the configuration file from the `data` directory, for example: `cp ~/git/tracing_software_packages/data/busybox-1.37.0.config .config`
1. create a directory to store `strace` output: `mkdir /tmp/trace`
1. trace a build using `strace`: `strace -o /tmp/trace/busybox-trace -e trace=chdir,getcwd,link,linkat,mkdir,newfstatat,open,openat,rename,renameat2,copy_file_range,sendfile,sendfile64,symlink,symlinkat,unlink,unlinkat,%process,dup,dup2,dup3,close,pipe,pipe2,tee,fchdir,write,pwrite64 -y -Y -qq -ttt -f -ff --seccomp-bpf -s 128 make`

Verify that there are trace result files in the directory `/tmp/trace`:

```
$ ls /tmp/trace | wc -l
5668
```

Then information from the trace files needs to be extracted and turned into
Python pickle files:

```
$ python trace_cli.py process-trace -b /tmp/busybox-1.37.0 -u project-123 -f /tmp/trace/ -o /tmp/pickles
```

Finally the pickle files can be used to further process data, such as creating
a process graph and output in JSON:

```
$ python trace_cli.py create-process-graph --pickle-dir=/tmp/pickles --output-format=json --output-file=/tmp/out.txt
```

## How to use

There are three distinct steps:

1. tracing a build using `strace`, see [running strace](doc/running_strace.md)
1. extract information from the trace file from step 1 and store in Python pickle files
1. processing the pickle files from the previous steps

## Funding

This project is funded through [NGI Zero Core](https://nlnet.nl/core), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program.
Learn more at the [NLnet project page](https://nlnet.nl/project/BuildTracing).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)


[TUD-SERG]:<https://web.archive.org/web/20130429174246/http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf>
[ASE-2014]:<https://rebels.cs.uwaterloo.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html>
