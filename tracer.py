#!/usr/bin/env python3

# Trace file processor
#
# Background information:
#
# * http://www.st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf
# * http://rebels.ece.mcgill.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2017-2024 - Armijn Hemel

import collections
import copy
import datetime
import os
import pathlib
import pickle
import random
import re
import shutil
import string
import sys

import click
import pydot

# these directories can be safely ignored as inputs or outputs
IGNORE_DIRECTORIES = ['/dev/', '/proc/', '/sys/']

# there are only a few syscalls that are interesting
INTERESTING_SYSCALLS = ['execve', 'open', 'openat', 'chdir', 'fchdir',
                        'rename', 'renameat2', 'clone', 'clone3',
                        'symlink', 'symlinkat']

# a global variable for storing results. This is kind of ugly, but since
# this program is running in a single thread it doesn't really matter.
RESULTS = {}

# regular expression for syscalls
# result: syscall
syscall_re = re.compile(r'\d+\.\d+\s+(?P<syscall>[\d\w_]+)\(')

# some precompiled regular expressions for interesting system calls
# valid filename characters:
# <>\w\d/\-+,.*$:;
chdir_re = re.compile(r"chdir\(\"(?P<path>[\w/\-_+,.]+)\"\s*\)\s+=\s+(?P<returncode>\d+)")
fchdir_re = re.compile(r"fchdir\((?P<fd>\d+)<(?P<path>.*)>\s*\)\s+=\s+(?P<returncode>\d+)")

# open
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

# dup
#dup
dup2_re = re.compile(r"dup2\((?P<old_fd>\d+)<(?P<old_fd_resolved>[\d\w/\-+_\.:\[\]]+)>,\s+(?P<new_fd>\d+)<?(?P<new_fd_resolved>[\d\w/\-+_\.:\[\]]+)?>?")
#dup3


class TraceProcess:
    '''Helper class to store information about a single process'''
    def __init__(self, parent_pid, pid):
        self._parent_pid = parent_pid
        self._parent_pid_label = parent_pid
        self._pid = pid
        self._pid_label = pid
        self._opened_files = []
        self._renamed_files = []
        self._children = []
        self._command = None

    @property
    def parent_pid(self):
        return self._parent_pid

    @property
    def pid(self):
        return self._pid

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, children):
        self._children = children

    @property
    def command(self):
        return self._command

    @command.setter
    def command(self, command):
        self._command = command

    @property
    def opened_files(self):
        return self._opened_files

    @opened_files.setter
    def opened_files(self, opened_files):
        self._opened_files = opened_files

    @property
    def renamed_files(self):
        return self._renamed_files

    @renamed_files.setter
    def renamed_files(self, renamed_files):
        self._renamed_files = renamed_files


class OpenedFile:
    '''Helper class to store information about a single opened file'''
    def __init__(self, cwd, flags, original_path, resolved_path, fd, timestamp):
        self._cwd = cwd
        self._flags = flags
        self._original_path = original_path
        self._resolved_path = resolved_path
        self._fd = fd
        self._timestamp = timestamp

    @property
    def cwd(self):
        return self._cwd

    @property
    def fd(self):
        return self._fd

    @fd.setter
    def fd(self, fd):
        self._fd = fd

    @property
    def flags(self):
        return self._flags

    @property
    def original_path(self):
        return self._original_path

    @property
    def resolved_path(self):
        return self._resolved_path

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def is_directory(self):
        return True if 'O_DIRECTORY' in self.flags else False

    @property
    def is_created(self):
        return True if 'O_CREAT' in self.flags else False

    @property
    def is_read(self):
        is_read = False
        if 'O_RDONLY' in self.flags or 'O_RDWR' in self.flags:
            is_read = True
        return is_read

    @property
    def is_read_only(self):
        return True if 'O_RDONLY' in self.flags else False

    @property
    def is_truncated(self):
        return True if 'O_TRUNC' in self.flags else False

    @property
    def is_written(self):
        is_write = False
        if 'O_WRONLY' in self.flags or 'O_RDWR' in self.flags:
            is_write = True
        return is_write

class RenamedFile:
    def __init__(self, timestamp, original_name, renamed_name):
        self._timestamp = timestamp
        self._original_name = original_name
        self._renamed_name = renamed_name

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def original_name(self):
        return self._original_name

    @property
    def renamed_name(self):
        return self._renamed_name



# TODO: remove this code
#def process_trace_line(line, syscall, pid_to_label):
#    # then look at the 'regular' lines
#    if syscall == 'open':
#        openres = open_re.search(line)
#        open_flags = []
#        if openres:
#
#            # now check the flags to see if a file is new. If so, it can
#            # be added to ignore_files
#            if "O_RDWR" in open_flags or "O_WRONLY" in open_flags:
#                if "O_CREAT" in open_flags:
#                    if "O_EXCL" in open_flags or "O_TRUNC" in open_flags:
#                        return

@click.group()
def app():
    pass


@app.command(short_help='Process strace output and write a pickle')
@click.option('--basepath', '-b', 'basepath', required=True,
              help='base path of source director during build',
              type=click.Path(path_type=pathlib.Path))
@click.option('--buildid', '-u', 'buildid', required=True,
              help='build id to be associated with the build', type=str)
@click.option('--tracefiles', '-f', 'tracefiles', required=True, help='path to trace files directory',
              type=click.Path(path_type=pathlib.Path))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
@click.option('--out', '-o', 'outfile', required=True,
              help='name of output file', type=click.File('wb'))
def process_trace(basepath, buildid, tracefiles, outfile, debug):
    if not basepath.is_absolute():
        raise click.ClickException("--basepath should be an absolute path")

    # a directory with all the tracefiles
    if not (tracefiles.exists() and tracefiles.is_dir()):
        raise click.ClickException(f"directory with trace files {tracefiles} does not exist or is not a directory")

    if buildid.strip() == "":
        raise click.ClickException("build identifier empty")

    # lookup table for PIDs to a unique PID label. This is done because PIDs
    # can be reused for processes especially for long running builds such
    # as the Linux kernel.
    pid_to_label = {}

    # store the (unique) paths of programs that are used during the build
    # process, typically in execve()
    exec_programs = set()

    # store which processes create other processes and vice versa
    parent_to_pid = {}

    # all opened files per pid (except non-existing files)
    opened_files_per_pid = {}

    # store the inputs and outputs per pid
    inputs_per_pid = {}
    outputs_per_pid= {}

    # a list of files created or overwritten, so can be ignored
    # later on for example when copying files.
    ignore_files = set()

    # find the start tracefile
    earliest = float('inf')
    for tracefile in tracefiles.glob('**/*'):
        pid = tracefile.suffix[1:]
        with open(tracefile, 'r') as candidate:
            for line in candidate:
                timestamp = float(line.split()[0])
                if timestamp < earliest:
                    rootfile = tracefile
                    earliest = timestamp
                break

    default_pid = rootfile.suffix[1:]

    if debug:
        print("ROOT PID", default_pid, file=sys.stderr)

    # process the first tracefile
    process_tracefile(rootfile, {'pid': 'root', 'opened': [], 'cwd': ''}, debug)

    # write the results to a pickle
    meta = {'buildid': buildid, 'root': default_pid, 'basepath': basepath}
    pickle.dump([meta, RESULTS], outfile)

    if debug:
        print("END RECONSTRUCTION", datetime.datetime.now(datetime.UTC).isoformat(), file=sys.stderr)

def get_open_files(infile):
    # load the data
    meta, data = pickle.load(infile)

    inputs = set()
    outputs = set()

    opened_files = set()
    renamed_files = set()
    for pid in data:
        for opened_file in data[pid].opened_files:
            if opened_file.is_directory:
                # directories can be safely skipped
                continue
            if opened_file.is_read:
                inputs.add(opened_file.resolved_path)
            if opened_file.is_written:
                outputs.add(opened_file.resolved_path)
        for opened_file in data[pid].renamed_files:
            renamed_files.add(opened_file)

    source_files = []
    system_files = []
    for input_file in sorted(inputs.difference(outputs)):
        if input_file.is_relative_to('/proc'):
            continue
        if input_file.is_relative_to('/dev'):
            continue
        if input_file == meta['basepath']:
            continue
        if input_file.is_relative_to(meta['basepath']):
            source_files.append(input_file)
        else:
            system_files.append(input_file)

    return (meta, source_files, system_files, renamed_files)

@app.command(short_help='Print all opened files')
@click.option('--pickle', '-p', 'infile', required=True,
              help='name of pickle file', type=click.File('rb'))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
def print_open_files(infile, debug):
    meta, source_files, system_files, renamed_files = get_open_files(infile)

    if system_files:
        print("System files:")
        for input_file in system_files:
            print(f"- {input_file}")
        print()
    if source_files:
        print("Source files:")
        for input_file in source_files:
            print_path = input_file.relative_to(meta['basepath'])
            print(f"- {print_path}")


@app.command(short_help='Copy source code files')
@click.option('--pickle', '-p', 'infile', required=True,
              help='name of pickle file', type=click.File('rb'))
@click.option('--source-directory', '-i', 'source_directory', required=True,
              help='source directory', type=click.Path(path_type=pathlib.Path))
@click.option('--output-directory', '-o', 'output_directory', required=True,
              help='output directory', type=click.Path(path_type=pathlib.Path))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
def copy_files(infile, source_directory, output_directory, debug):
    # a directory with all the tracefiles
    if not source_directory.is_dir():
        raise click.ClickException(f"{source_directory} does not exist or is not a directory")

    if not output_directory.is_dir():
        raise click.ClickException(f"{output_directory} does not exist or is not a directory")

    meta, source_files, system_files, renamed_files = get_open_files(infile)

    if source_files:
        for input_file in source_files:
            source_file = input_file.relative_to(meta['basepath'])
            copy_path = source_directory / source_file
            if not copy_path.exists():
                print(f"Expected path {copy_path} does not exist, exiting...", file=sys.stderr)
                sys.exit()

            destination = output_directory / source_file

            # first make sure the subdirectory exists
            if source_file.parent != '.':
                destination.parent.mkdir(parents=True, exist_ok=True)

            # then copy the file
            # TODO: symlinks
            if debug:
                print(f"copying {source_file}", file=sys.stderr)
            shutil.copy(copy_path, destination)


@app.command(short_help='Process pickle file output')
@click.option('--pickle', '-p', 'infile', required=True,
              help='name of pickle file', type=click.File('rb'))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
@click.option('--path', '-f', 'searchpath', type=click.Path(path_type=pathlib.Path),
              help='path to be searched', required=True)
def traverse(infile, debug, searchpath):
    # load the data
    meta, data = pickle.load(infile)

    resolved_searchpath = meta['basepath'] / searchpath

    # The most interesting data is opened files.
    # These files can be divided into a few categories:
    #
    # 1. files that are only read (input)
    # 2. files that are only written (output)
    # 3. files that are read and written (input and output)
    #
    # Files in the first category can contain source code files
    # (interesting), but also dependencies of programs that are
    # run (perhaps less interesting).
    #
    # Files in the second category are temporary files, or
    # build artifacts (interesting)
    #
    # Files in the third category are most likely temporary
    # files.

    inputs_per_pid = {}
    outputs_per_pid = {}
    pids_per_input = {}
    pids_per_output = {}

    # store inputs and outputs per pid
    # and vice versa
    for pid in data:
        for opened_file in data[pid].opened_files:
            if opened_file.is_directory:
                # directories can be safely skipped
                continue
            if opened_file.is_read:
                if pid not in inputs_per_pid:
                    inputs_per_pid[pid] = []
                inputs_per_pid[pid].append(opened_file)
                if opened_file.resolved_path not in pids_per_input:
                     pids_per_input[opened_file.resolved_path] = []
                pids_per_input[opened_file.resolved_path].append((pid, opened_file.timestamp))
            if opened_file.is_written:
                if pid not in outputs_per_pid:
                    outputs_per_pid[pid] = []
                outputs_per_pid[pid].append(opened_file)
                if opened_file.resolved_path not in pids_per_output:
                     pids_per_output[opened_file.resolved_path] = []
                pids_per_output[opened_file.resolved_path].append((pid, opened_file.timestamp))

    if resolved_searchpath not in pids_per_output:
        print(f"Path {searchpath} could not be found as an output, exiting...", file=sys.stderr)
        sys.exit(1)

    # in case there are multiple
    latest = float(0)
    latest_pid = None
    for pid, timestamp in pids_per_output[resolved_searchpath]:
        if timestamp > latest:
            latest = timestamp
            latest_pid = pid

    inputs_per_output = set()

    # recursively walk inputs/outputs
    pid_deque = collections.deque()
    pid_deque.append(latest_pid)

    while True:
        try:
            pid = pid_deque.popleft()
            for i in inputs_per_pid[pid]:
                print(i.resolved_path)
            #print(pid, inputs_per_pid[pid])
        except IndexError:
            break


    '''
    graph = pydot.Dot("pid_graph", graph_type="graph")
    first_node = pydot.Node(meta['root'])
    graph.add_node(first_node)

    pid_deque = collections.deque()
    pid_deque.append((first_node, meta['root']))

    while True:
        try:
            node, pid = pid_deque.popleft()
            for child_pid in data[pid].children:
                node = pydot.Node(child_pid)
                graph.add_node(node)
                edge = pydot.Edge(pid, child_pid)
                graph.add_edge(edge)
                pid_deque.append((node, child_pid))
        except IndexError:
            break
    '''


def process_tracefile(tracefile, parent, debug):
    # local information
    children = []
    command = None
    closed = set()
    opened = []
    renamed = []
    pid = tracefile.suffix[1:]

    # data inherited from the parent process
    parent_pid = parent['pid']
    parent_opened = parent['opened']
    cwd = parent['cwd']

    open_fds = {}
    for opened_file in parent_opened:
        open_fds[opened_file.fd] = opened_file

    trace_process = TraceProcess(parent_pid, pid)

    with open(tracefile, 'r') as file_to_process:
        for line in file_to_process:
            if '=' not in line:
                continue

            # grab the name of the system call.
            syscall_result = syscall_re.match(line)
            if not syscall_result:
                continue

            syscall = syscall_result.group('syscall')

            # skip uninteresting system calls
            if syscall in ['wait4', 'exit_group']:
                continue

            if debug:
                print(pid, syscall, file=sys.stderr)

            if syscall in ['chdir', 'fchdir']:
                if not line.rsplit('=', maxsplit=1)[1].strip().startswith('0'):
                    continue
                if syscall == 'chdir':
                    chdir_res = chdir_re.search(line)
                elif syscall == 'fchdir':
                    chdir_res = fchdir_re.search(line)
                if chdir_res:
                    chdir_path = pathlib.Path(chdir_res.group('path'))
                    if chdir_path == '.':
                        continue

                    # absolute paths can be stored immediately
                    # while relative paths need to be rewritten
                    # first (TODO)
                    if chdir_path.is_absolute():
                        cwd = chdir_path
                    else:
                        cwd = pathlib.Path(os.path.normpath(cwd / chdir_path))
            elif syscall in ['clone', 'clone3', 'vfork']:
                # cloned/forked processes inherit the cwd of the parent process.
                # First retrieve the information for the parent process and
                # store it for the cloned process.
                flags = []
                if syscall == 'clone':
                    cloneres = clone_re.search(line)
                elif syscall == 'clone3':
                    cloneres = clone3_re.search(line)
                elif syscall == 'vfork':
                    cloneres = vfork_re.search(line)
                if not cloneres:
                    continue

                # this is the PID of the cloned process
                clone_pid = cloneres.group('clone_pid')
                if syscall != 'vfork':
                    flags = cloneres.group('flags')

                # store the clone as a child of the parent process
                children.append(clone_pid)

                children_opened = open_fds.values()

                # now process the child process
                child_tracefile = tracefile.with_suffix(f'.{clone_pid}')
                process_tracefile(child_tracefile, {'pid': pid, 'opened': children_opened, 'cwd': cwd}, debug)

            elif syscall == 'close':
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                close_res = close_re.search(line)
                if not close_res:
                    continue
                closed.add(close_res.group('path'))
                fd = close_res.group('fd')
                try:
                    del open_fds[fd]
                except:
                    pass
            elif syscall == 'dup2':
                dup2_res = dup2_re.search(line)
                if not dup2_res:
                    continue

                old_fd = dup2_res.group('old_fd')
                new_fd = dup2_res.group('new_fd')

                # TODO: is this actually correct?
                if old_fd in open_fds:
                    new_file = copy.deepcopy(open_fds[old_fd])
                    new_file.fd = new_fd
                    open_fds[new_fd] = new_file
            elif syscall == 'execve':
                # store the programs that are (successfully) executed
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                execveres = execve_re.search(line)
                if execveres:
                    command = {'command': execveres.group('command'), 'args': execveres.group('args')}
            elif syscall == 'getcwd':
                getcwd_result = getcwd_re.search(line)
                if getcwd_result:
                    cwd = pathlib.Path(os.path.normpath(getcwd_result.group('cwd')))
            elif syscall in ['openat']:
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                openres = openat_re.search(line)
                if openres:
                    # store both the (resolved) original path
                    # and the fully resolved path (related to symbolic links)
                    orig_path = pathlib.Path(openres.group('cwd')) / openres.group('path')
                    resolved_path = pathlib.Path(openres.group('resolved_path'))
                    flags = openres.group('flags').split('|')
                    fd = openres.group('result_fd')

                    already_opened = False
                    for o in opened:
                        if o.original_path == orig_path:
                            already_opened = True
                            break
                    if not already_opened:
                        timestamp = float(line.split(' ', maxsplit=1)[0])
                        opened_file = OpenedFile(pathlib.Path(openres.group('cwd')), flags, orig_path, resolved_path, fd, timestamp)
                        opened.append(opened_file)
                        open_fds[fd] = opened_file
            elif syscall in ['rename', 'renameat2']:
                # renaming is important to track.
                # Example: in the Linux kernel the file include/config/auto.conf
                # is "created" by renaming an already existing file.
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                if syscall == 'rename':
                    rename_res = rename_re.search(line)
                else:
                    rename_res = renameat2_re.search(line)
                if rename_res:
                    timestamp = float(line.split(' ', maxsplit=1)[0])
                    if syscall == 'rename':
                        original_name = pathlib.Path(rename_res.group('original'))
                        renamed_name = pathlib.Path(rename_res.group('renamed'))
                    elif syscall == 'renameat2':
                        original_name = pathlib.Path(rename_res.group('cwd')) / rename_res.group('original')
                        renamed_name = pathlib.Path(rename_res.group('cwd2'))/ rename_res.group('renamed')
                    renamed_file = RenamedFile(timestamp, original_name, renamed_name)
                    renamed.append(renamed_file)
            elif syscall in ['symlinkat']:
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                if syscall == 'symlinkat':
                    symlink_res = symlinkat_re.search(line)
                if symlink_res:
                    timestamp = float(line.split(' ', maxsplit=1)[0])
                    if syscall == 'symlinkat':
                        target = pathlib.Path(symlink_res.group('target'))
                        linkpath = pathlib.Path(symlink_res.group('linkpath'))

    # store the results for the trace process
    trace_process.children = children
    trace_process.opened_files = opened
    trace_process.renamed_files = renamed
    trace_process.command = command

    # store the results in the global RESULTS dict
    RESULTS[pid] = trace_process

if __name__ == "__main__":
    app()
