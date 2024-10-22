# Which calls to trace?

The following calls are currently traced (but not all are processed):

* `getcwd` : current working directory is queried
* `chdir` and `fchdir` : current working directory is changed
* `link` and `linkat` : hard link is created (not processed)
* `mkdir` : directory is created
* `newfstatat` : stat information of a file is queried
* `open` and `openat`: file is opened
* `close` : file is closed (not processed)
* `rename` and `renameat2` : file is renamed
* `sendfile` : data is sent to a file (not processed)
* `symlink` and `symlinkat` : symbolic link to a file is created
* `unlink` and `unlinkat` : file is deleted (not processed)
* `dup` and `dup2` and `dup3` : file descriptor is duplicated
* `pipe` : pipe is created (not processed)
* `tee` : read from stdin and write to stdout
* `%process` : all process related calls (`vfork`, `clone`, `clone3`)

## `newfstatat`

This system call `newfstatat` is important to process, as some build processes
depend on it. For example `make` uses it to determine if files need to be
rebuilt or not.

This is important to track for the `copy-files` functionality that is used to
verify using rebuilds. Because the `make` process will barf if some of these
files are not found, it means they are needed for the rebuild, even if the
files themselves are not used at all during the build process (which could
indicate an inefficiency in the build process).
