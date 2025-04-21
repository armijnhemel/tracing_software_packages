# Processes and files

A goal of tracing build processes is to eventually find out which files were
an input to binaries that were built. By doing this it is possible to have a
much more nuanced view on what happened.

There are a few levels for this:

* build level
* process level
* flow level

The build level is fairly simple: all files that were opened during the build
are an input to all of the binaries that were created. This is very coarse, but
could already be better than looking at just the source code files and assuming
that all are an input. As an example: the Linux kernel is highly configurable
and typically just 10% or so of the source code files end up in any of the
binaries created during the build. In the worst case all the files are opened
and the result is the same as during a source code scan.

Of course, this is not a realistic view of the source code. As an example take
the `glibc` package, of which the library parts are under the LGPL license, but
the tools are under GPL. The GPL source code for the tools is not used in the
library parts section and just looking at the level of the entire build will
miss this.

By looking at the individual processes and which inputs and ouputs they have it
already becomes a lot more granular: typically processes only create one file
from multiple inputs, unless processes are running for a very long time and
create multiple files. In that case looking at which files have been opened
makes the information even more granular.

There are a few caveats: when parsing trace files and keeping state it is
important to realise that the order in which files are opened is important,
but state doesn't say anything. A file that has been opened, read and closed
obviously cannot be an input for a file that has already been written and
closed, but it could be used as an input for a file that is written later,
even if the input was already closed (because contents were read into memory).

The following picture tries to describe it. On the left are input files, on the
right are output files, the box in the middle is the process and process run
time is from top to bottom:

```
       +----+
A ---> |    |
       |    | --> X (input: A)
       |    |
B ---> |    |
       |    | --> Y (input: A & B)
       +----+
```

Because B wasn't opened yet when X was written, it cannot be an input, but for
Y it cannot be excluded that A is an input.

To be even more accurate there could be checks to see if data was actually read
from the inputs or written to the outputs, by looking at `read`, `write`,
`sendfile`, `copy_file_range`, and so on.

## Pipes

The [original paper](TUD-SERG-2012-010.pdf) says on page 9:

```
Most importantly, the trace analyser does not trace file descriptors and
inter-process communication (e.g. through pipes) yet. For instance, it fails
to see that the task patch in the command cat foo.patch | patch bar.c has a
dependency on foo.patch; it only sees that patch reads and recreates bar.c.
```

File descriptors to pipes can be passed around from parent processes to child
processes (or children of child processes, or children of children of child
processes, etc.). This allows child processes to communicate with parent
processes. Tracking these properly is a challenge.
