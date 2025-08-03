# Processing results

After running `strace` the results (stored as pickle files in a directory) can
be processed to extract results. There are a few possibly interesting uses for
the data.

## Printing all opened files

The command:

```
$ python trace_cli.py print-open-files --pickle-dir=/path/to/pickle/dir
```

will print all the opened files and splits them into two categories:

1. system files: files present on the system, including other executables,
   system header files, shared libraries, and so on (but excludes files in
   `/dev/`, `/proc/` and `/sys/`)
2. source files: anything from the source code directory. This might contain
   build artifacts and not just source code files (this will added as an option
   later)

## Copying all opened files to a separate directory

It can come in handy to copy only the files that are used in a build to reduce
the problem space for example when scanning for security issues, or provenance
detection. Sometimes the search space can be dramatically reduced. The most
extreme example is, as almost always, the Linux kernel, where only a small
percentage of the number of total files is used.

Exceptions are build processes where all files are opened. A good example of
this is BusyBox which during compilation opens every C source code file to
read some configuration data embedded in the source code files. In this case
the filtered set of data is (almost) the same as the original set of data (in
the case of BusyBox a few C files are not copied, namely some example scripts
and the files needed for `make menuconfig`).

## Create a graph for each generated binary
