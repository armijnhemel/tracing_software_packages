import re

# regular expression for syscalls
# result: syscall
syscall_re = re.compile(r'\d+\.\d+\s+(?P<syscall>[\d\w_]+)\(')

# some precompiled regular expressions for interesting system calls
# valid filename characters:
# <>\w\d/\-+,.*$:;
chdir_re = re.compile(r"chdir\(\"(?P<path>[\w/\-_+,.]+)\"\s*\)\s+=\s+(?P<returncode>\d+)")
fchdir_re = re.compile(r"fchdir\((?P<fd>\d+)<(?P<path>.*)>\s*\)\s+=\s+(?P<returncode>\d+)")

# open and openat
# Since glibc 2.26 this always defaults to openat(). This change was introduced
# sometime in 2017, around Fedora 27 (for reference).
open_re = re.compile(r"open\(\"([<>\w/\-+,.*$:;]+)\", ([\w|]+)(?:,\s+\d+)?\)\s+= (\-?\d+)<(.*)>$")
openat_re = re.compile(r"openat\((?P<open_fd>\w+)<(?P<cwd>.*)>, \"(?P<path>[<>\w/\-+,.*$:;]+)\", (?P<flags>[\w|]+)(?:,\s+\d+)?\)\s+=\s+(?P<result_fd>\-?\d+)<(?P<resolved_path>.*)>$")

# close
close_re = re.compile(r"close\((?P<fd>\d+)<(?P<path>[\w\d:+/_\-\.\[\]]+)>\)\s+=\s+(?P<returncode>\d+)")

# getcwd
getcwd_re = re.compile(r"getcwd\(\"(?P<cwd>[\w/\-+,.]+)\",\s+\d+\)\s+=\s+(?P<fd>\-?\d+)")

# rename and renameat2
rename_re = re.compile(r"rename\(\"(?P<original>[\w/\-+,.]+)\",\s+\"(?P<renamed>[\w/\-+,.]+)\"\)\s+=\s+(?P<returncode>\d+)")
renameat2_re = re.compile(r"renameat2\((?P<open_fd>\w+)<(?P<cwd>[\w\d\s:+/_\-\.,\s]+)>,\s+\"(?P<original>[\w\d\s\./\-+]+)\",\s+(?P<open_fd2>\w+)<(?P<cwd2>[\w\d\s:+/_\-\.,\s]+)>,\s+\"(?P<renamed>[\w\d\s\./\-+]+)\",\s(?P<flags>\w+)\)\s+=\s+(?P<returncode>\d+)")

# clone
clone_re = re.compile(r"clone\([\w/\-+,.=]+,\s+(?P<flags>[\w|=]+),\s+[\w=]+?\)\s+=\s+(?P<clone_pid>\-?\d+)<(?P<command>.*)>")
clone3_re = re.compile(r"clone3\({flags=(?P<flags>[\w_|]+),\s+[\w{}=|,\s<>\[\]]+\)\s+=\s+(?P<clone_pid>\d+)<(?P<command>.*)>")

# vfork
vfork_re = re.compile(r"vfork\(\s*\)\s*=\s*(?P<clone_pid>\d+)<(?P<command>.*)>")

# execve
execve_re = re.compile(r"execve\(\"(?P<command>.*)\",\s*\[(?P<args>.*)\],\s+0x\w+\s+/\*\s+\d+\s+vars\s+\*/\)\s*=\s*(?P<returncode>\d+)")

# symlink
# symlink_re =
symlinkat_re = re.compile(r"symlinkat\(\"(?P<target>[\w\d\s/\.+\-_,]+)\",\s+(?P<open_fd>\w+)<(?P<cwd>[\w\d\s:+/_\-\.,\s]+)>,\s+\"(?P<linkpath>[\w\d\s/\.+\-_,]+)\"\)\s+=\s+(?P<returncode>\d+)")

# dup - fd_resolved only needs to be grabbed once as it will always be the same for both fds.
dup_re = re.compile(r"dup\((?P<old_fd>\d+)<(?P<fd_resolved>[\d\w/\-+_\.:\[\]]+)>\)\s+=\s+(?P<new_fd>\d+)")

# dup2 & dup3
dup2_re = re.compile(r"dup2\((?P<old_fd>\d+)<(?P<fd_resolved>[\d\w/\-+_\.:\[\]]+)>,\s+(?P<new_fd>\d+)")
#dup3

# pipe2
# Example: pipe2([3<pipe:[1714585]>, 4<pipe:[1714585]>], O_CLOEXEC) = 0
pipe2_re = re.compile(r"pipe2\(\[(?P<read_fd>\d+)<pipe:\[(?P<read_pipe>\d+)\]>,\s+(?P<write_fd>\d+)<pipe:\[(?P<write_pipe>\d+)\]>\],\s+[\w\d]+\)\s+=\s+(?P<returncode>\d+)")

# stat, statx, newfstatat
newfstatat_re = re.compile(r"newfstatat\((?P<open_fd>\w+)<(?P<cwd>[\w\d\s:+/_\-\.,\s]+)>,\s+\"(?P<path>[\w\d\s\./\-+]*)\",\s+{")
#statx = re.compile(r"statx\(")
