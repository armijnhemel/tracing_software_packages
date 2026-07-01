# Processing results

After running `strace` the results (stored as pickle files in a directory) can
be processed to extract results. There are a few possibly interesting uses for
the data.

To turn the trace files to pickle files use the following command:

```
$ python trace_cli.py process-trace -b basepath -u project-identifier -f /path/to/trace/files -o /path/to/output/directory
```

for example:

```
$ python trace_cli.py process-trace -b /home/armijn/tmp/trace/linux-6.11 -u project-123 -f ~/tmp/trace/linux-trace/ -o /tmp/bla
```

A few notes:

1. the output directory should not already exist. It will be created automatically.
2. the basepath is merely used for nicer reporting
3. the build identifier isn't used at the moment for reporting, but is just a
   little bit of meta information to make it easier to distinguish builds. It
   can safely be set to a dummy value.

The end result of running this is a directory with Python pickles as well as a
JSON file with meta information called (unsurprisingly) `meta.json`, which will
look like this:

```
{
    "buildid": "project-123",
    "root": "15306",
    "basepath": "/home/armijn/tmp/trace/linux-6.11"
}
```

and stores the build identifier, the basepath (for pretty printing) and the number
of the first process that runs (the "root" of the process that was traced).

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
