#!/usr/bin/env python3

# Trace file processor
#
# Background information:
#
# * https://web.archive.org/web/20130429174246/https://st.ewi.tudelft.nl/~sander/pdf/publications/TUD-SERG-2012-010.pdf
# * https://rebels.cs.uwaterloo.ca/confpaper/2014/09/14/tracing-software-build-processes-to-uncover-license-compliance-inconsistencies.html
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2017-2026 - Armijn Hemel

import collections
import copy
import datetime
import json
import os
import pathlib
import pickle
import shutil
import sys

import click
import graphviz

import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from tracer import syscalls
from tracer import tracer


# these system calls can safely be ignored as inputs or outputs
IGNORE_SYSCALLS = ['wait4', 'exit_group', 'lseek', 'utimensat']

# these directories can (possibly) safely be ignored as inputs or outputs
IGNORE_DIRECTORIES = ['/dev/', '/proc/', '/sys/']

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


@app.command(short_help='Process strace output and write a pickle for each trace file')
@click.option('--basepath', '-b', 'basepath', required=True,
              help='base path of source director during build',
              type=click.Path(path_type=pathlib.Path))
@click.option('--buildid', '-u', 'buildid', required=True,
              help='build id to be associated with the build', type=str)
@click.option('--tracefile', '-f', 'tracefile', required=True,
              help='path to trace files directory', type=click.File('r'))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
@click.option('--force', is_flag=True, help='force processing data')
@click.option('--out', '-o', 'output_directory', required=True,
              help='name of output directory', type=click.Path(path_type=pathlib.Path))
def process_trace(basepath, buildid, tracefile, output_directory, debug, force):
    '''Trace processor'''
    if not basepath.is_absolute():
        raise click.ClickException("--basepath should be an absolute path")

    if buildid.strip() == "":
        raise click.ClickException("build identifier empty")

    # directory where pickles should be written to
    try:
        if output_directory.exists() and not force:
            raise click.ClickException(f"{output_directory} already exists")
    except PermissionError as e:
        raise click.ClickException(f"Permission error for {output_directory}") from e

    try:
        output_directory.mkdir(exist_ok=True)
    except Exception as e:
        raise click.ClickException(f"Could not create {output_directory}") from e

    # set the initial "current working directory"
    cwd = ''

    # set the root PID
    root_pid = None

    # store the known pids
    known_pids = set()

    # store mappings for pids to parents and parents to pids
    parent_to_pid = {}
    pid_to_parent = {}

    # store trace processes per PID
    trace_processes = {}

    # some temporary storage for like flags for some unfinished
    # system calls (clone, clone3, etc.) stored per pid
    temp_data = {}

    # open the tracefile and process each line
    for line in tracefile:
        if not root_pid:
            root_pid = int(line.split('<', maxsplit=1)[0])
            pid_to_parent[root_pid] = None
            if debug:
                print("ROOT PID", root_pid, file=sys.stderr)
            trace_processes[root_pid] = tracer.TraceProcess(root_pid, None)
            known_pids.add(root_pid)

        # process each line. Extract pid and timestamp first,
        # then extract the syscall using regex
        pid_command, rest_of_line = line.strip().split(' ', maxsplit=1)
        pid = int(pid_command.split('<', maxsplit=1)[0])
        cur_command = pid_command.split('<', maxsplit=1)[1][:-1]

        # unfinished/resumed system calls should be processed separately
        is_unfinished = False
        is_resumed = False

        # grab the name of the system call.
        if '<... ' in rest_of_line and ' resumed>' in rest_of_line:
            syscall_result = syscalls.syscall_resumed_re.match(rest_of_line)
            if not syscall_result:
                continue
            is_resumed = True
        else:
            syscall_result = syscalls.syscall_re.match(rest_of_line)
            if not syscall_result:
                continue

        syscall = syscall_result.group('syscall')

        # skip uninteresting system calls
        if syscall in IGNORE_SYSCALLS:
            continue

        # Check if the pid is a known pid. There are situations where this
        # can happen:
        #
        # 1. a system call creating the process was interrupted (example: clone3) and later resumed
        # 2. the trace file is corrupted
        if pid not in known_pids:
            new_trace_process = tracer.TraceProcess(pid, None)

            # store the trace process
            trace_processes[pid] = new_trace_process

            # add clone_pid to the set of known pids
            known_pids.add(pid)

        if rest_of_line.endswith('<unfinished ...>'):
            is_unfinished = True

        if syscall in ['clone', 'clone3', 'vfork']:
            # Check to see if a new process was created.
            # In certain instances (such as vfork and clone3) the
            # system call could be in an "unfinished" state
            if syscall == 'clone':
                if is_unfinished:
                    # There are some possibly interesting flags that can be
                    # extracted, so store them.
                    continue
                if is_resumed:
                    cloneres = syscalls.clone_resumed_re.search(line)
                else:
                    cloneres = syscalls.clone_re.search(line)
            elif syscall == 'clone3':
                if is_unfinished:
                    # There are some possibly interesting flags that can be
                    # extracted, so store them.
                    continue
                if is_resumed:
                    cloneres = syscalls.clone3_resumed_re.search(line)
                else:
                    cloneres = syscalls.clone3_re.search(line)
            elif syscall == 'vfork':
                if is_unfinished:
                    # There actually isn't any information to
                    # record, as it will look like this:
                    #
                    # vfork( <unfinished ...>
                    continue
                if is_resumed:
                    cloneres = syscalls.vfork_resumed_re.search(line)
                else:
                    cloneres = syscalls.vfork_re.search(line)
            if not cloneres:
                if debug:
                    print('clone/clone3/vfork failed:', line, file=sys.stderr)
                continue

            # extract the PID of the cloned process
            clone_pid = int(cloneres.group('clone_pid'))

            # store the clone pid in the various PID mappings
            pid_to_parent[clone_pid] = pid
            if pid not in parent_to_pid:
                parent_to_pid[pid] = []
            parent_to_pid[pid].append(clone_pid)

            # create a new TraceProcess if it wasn't already created
            if clone_pid not in trace_processes:
                new_trace_process = tracer.TraceProcess(clone_pid, pid)

                # explicitly set the working directory to the current working
                # directory of the parent process
                new_trace_process.cwd = trace_processes[pid].cwd

                # copy all the parents' open file descriptors
                for fd in trace_processes[pid].open_fds:
                    new_trace_process.add_open_fd(fd, copy.copy(trace_processes[pid].open_fds[fd]))

                # store the trace process
                trace_processes[clone_pid] = new_trace_process

                # add clone_pid to the set of known pids
                known_pids.add(clone_pid)
            else:
                # set the cwd for the process to the parent's cwd if none
                # has been set by chdir/fchdir/getcwd
                if not trace_processes[clone_pid].cwd:
                    trace_processes[clone_pid].cwd = trace_processes[pid].cwd
                if not trace_processes[clone_pid].parent_pid:
                    trace_processes[clone_pid].parent_pid = pid

                # copy all the parents' open file descriptors
                for fd in trace_processes[pid].open_fds:
                    trace_processes[clone_pid].add_open_fd(fd, copy.copy(trace_processes[pid].open_fds[fd]))

                # close all the file descriptors that should be closed
                if clone_pid in temp_data:
                    if 'close' in temp_data[clone_pid]:
                        while True:
                            try:
                                fd = temp_data[clone_pid]['close'].pop()
                                trace_processes[clone_pid].remove_fd(fd)
                            except IndexError:
                                break
        elif syscall in ['chdir', 'fchdir']:
            if is_unfinished:
                chdir_res = syscalls.chdir_unfinished_re.search(rest_of_line)
                if chdir_res:
                    # store the temporary data in temp_data
                    chdir_path = pathlib.Path(chdir_res.group('path'))
                    if pid not in temp_data:
                        temp_data[pid] = {}
                    temp_data[pid][syscall] = {'chdir_path': chdir_path}
                continue
            if not rest_of_line.rsplit('=', maxsplit=1)[1].strip().startswith('0'):
                continue
            if syscall == 'chdir':
                chdir_res = syscalls.chdir_re.search(line)
            elif syscall == 'fchdir':
                chdir_res = syscalls.fchdir_re.search(line)
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
                if pid in trace_processes:
                    trace_processes[pid].cwd = cwd
                else:
                    # TODO: what to do here?
                    pass
            elif debug:
                print('chdir/fchdir failed:', line, file=sys.stderr)
        elif syscall == 'getcwd':
            getcwd_result = syscalls.getcwd_re.search(line)
            if getcwd_result:
                cwd = pathlib.Path(os.path.normpath(getcwd_result.group('cwd')))
                if pid in trace_processes:
                    trace_processes[pid].cwd = cwd
                else:
                    # TODO: what to do here?
                    pass
            elif debug:
                print('getcwd failed:', line, file=sys.stderr)
        elif syscall == 'getpid':
            # create a placeholder for commands. This value is typically
            # overwritten when parsing execve
            getpid_results = syscalls.getpid_re.search(line)
            if getpid_results:
                command = {'command': getpid_results.groups()[0], 'args': None}
                trace_processes[pid].command = command
            elif debug:
                print('getpid failed:', line.strip(), file=sys.stderr)
        elif syscall in ['openat']:
            if is_unfinished:
                openres = syscalls.openat_unfinished_re.search(rest_of_line)
                if openres:
                    # store the temporary data in temp_data
                    orig_path = pathlib.Path(openres.group('cwd')) / openres.group('path')
                    cwd = pathlib.Path(openres.group('cwd'))
                    flags = openres.group('flags').split('|')
                    if pid not in temp_data:
                        temp_data[pid] = {}
                    temp_data[pid][syscall] = {'orig_path': orig_path, 'flags': flags, 'cwd': cwd}
                    continue
            if rest_of_line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                continue
            if is_resumed:
                openres = syscalls.openat_resumed_re.search(rest_of_line)
                if openres:
                    # extract the remaining data and remove the temporary data
                    resolved_path = pathlib.Path(openres.group('resolved_path'))
                    fd = int(openres.group('result_fd'))
                    orig_path = temp_data[pid][syscall]['orig_path']
                    flags = temp_data[pid][syscall]['flags']
                    cwd = temp_data[pid][syscall]['cwd']
                    del temp_data[pid][syscall]
            else:
                openres = syscalls.openat_re.search(rest_of_line)
                if openres:
                    # Store both the (resolved) original path and the fully resolved
                    # path (related to symbolic links) for the process.
                    # This include all files that are opened, including in
                    # places such as /dev and /proc which are defined in IGNORE_DIRECTORIES.
                    orig_path = pathlib.Path(openres.group('cwd')) / openres.group('path')
                    resolved_path = pathlib.Path(openres.group('resolved_path'))
                    cwd = pathlib.Path(openres.group('cwd'))
                    flags = openres.group('flags').split('|')
                    fd = int(openres.group('result_fd'))

            if openres:
                if debug:
                    print(f"PROCESS {pid} OPENED {resolved_path}",
                          file=sys.stderr)

                # check to see if the file was already opened before by this process
                already_opened = trace_processes[pid].is_opened(orig_path)
                if not already_opened:
                    timestamp = float(rest_of_line.split(' ', maxsplit=1)[0])
                    opened_file = tracer.OpenedFile(cwd, flags, orig_path, resolved_path, fd, timestamp)
                    trace_processes[pid].add_opened_file(opened_file)
                    trace_processes[pid].add_open_fd(fd, opened_file)
                    #print(trace_processes[pid].open_fds)
                #trace_processes[pid].open_fds = list(open_fds.values())
            elif debug:
                print('openat failed:', line.strip(), file=sys.stderr)
        elif syscall == 'close':
            # Process close() calls to close file descriptors. These calls
            # are either successful (in which case the file descriptor is closed)
            # or there is an error that the file descriptor is a bad file
            # descriptor and there is no file descriptor with that number.
            # Other error codes are actually irrelevant, as they relate to
            # interrupted builds, NFS, I/O errors, etc.
            #
            # There is a case where file descriptors can be closed before
            # they have been recorded in a process. An example (redacted for
            # readability):
            #
            # 13788<gcc> 1793197494.246146 vfork( <unfinished ...>
            # 13789<gcc> 1793197494.246494 close(3<pipe:[90683]>) = 0
            # 13789<gcc> 1793197494.246825 execve("/usr/libexec/gcc/x86_64-redhat-linux/13/cc1", [...], 0x1b0feed0 /* 77 vars */ <unfinished ...>
            # 13788<gcc> 1793197494.247203 <... vfork resumed>) = 13789<cc1>
            #
            # Here the file descriptor 3 (pipe:[90683]) is closed before it
            # has been recorded as an open file descriptor, because the parent
            # process (from which open file descriptors are inherited) isn't
            # known yet. This means that if the parent process isn't known,
            # then the file descriptor should be removed immediately after
            # the file descriptors from the parent have been copied, so any
            # file descriptors that should be closed as soon as the parent
            # process is known should be stored, except in the top level
            # process.
            if '=' in rest_of_line and rest_of_line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                # ignore -1 EBADF (Bad file descriptor)
                continue
            if is_resumed:
                # ignore resumed calls
                continue

            # process unfinished and regular calls to close()
            if is_unfinished:
                close_res = syscalls.close_unfinished_re.search(rest_of_line)
            else:
                close_res = syscalls.close_re.search(rest_of_line)
            if not close_res:
                if debug:
                    print('close failed:', line.strip(), file=sys.stderr)
                continue

            trace_processes[pid].add_closed_file(close_res.group('path'))
            fd = int(close_res.group('fd'))

            if pid == root_pid or trace_processes[pid].parent_pid:
                # remove fds for processes for which there is a known
                # parent, or if the process is the root process (for which
                # there is no root process)
                trace_processes[pid].remove_fd(fd)
            else:
                # store file descriptors that should be closed
                # immediately as soon as the parent's file descriptors
                # are copied to the new process.
                if pid not in temp_data:
                    temp_data[pid] = {}
                if 'close' not in temp_data[pid]:
                    temp_data[pid]['close'] = []
                temp_data[pid]['close'].append(fd)
        elif syscall == 'pipe2':
            # Extract file descriptor numbers and pipe number
            # man 7 pipe
            if is_unfinished:
                continue
            if is_resumed:
                pipe_res = syscalls.pipe2_resumed_re.search(line)
            else:
                pipe_res = syscalls.pipe2_re.search(line)
            if not pipe_res:
                if debug:
                    print('pipe2 failed:', line, file=sys.stderr)
                continue

            # each pipe has a read and write file descriptor associated with it
            read_fd = pipe_res.group('read_fd')
            write_fd = pipe_res.group('write_fd')

            # in the strace output there are two values for the pipe
            # namely the read end and the write end. These are always
            # identical, but extracted for completeness sake.
            read_pipe = pipe_res.group('read_pipe')
            write_pipe = pipe_res.group('write_pipe')
        elif syscall == 'newfstatat':
            if is_unfinished:
                newfstatat_res = syscalls.newfstatat_unfinished_re.search(rest_of_line)
                if not newfstatat_res:
                    if debug:
                        print('newfstatat failed:', line, file=sys.stderr)
                    continue
                orig_path = pathlib.Path(newfstatat_res.group('cwd')) / newfstatat_res.group('path')
                fd = newfstatat_res.group('open_fd')

                timestamp = float(rest_of_line.split(' ', maxsplit=1)[0])
                stat_file = tracer.StatFile(pathlib.Path(newfstatat_res.group('cwd')), orig_path, fd, timestamp)
                if pid not in temp_data:
                    temp_data[pid] = {}
                if 'newfstatat' not in temp_data[pid]:
                    temp_data[pid]['newfstatat'] = stat_file
                continue
            if is_resumed:
                # grab the statted file
                if pid not in temp_data:
                    continue
                if 'newfstatat' not in temp_data[pid]:
                    continue
                statfile = temp_data[pid].pop('newfstatat')
                if rest_of_line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                trace_processes[pid].add_statted_file(stat_file)
                continue
            if rest_of_line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                continue

            # process regular lines
            newfstatat_res = syscalls.newfstatat_re.search(rest_of_line)
            if newfstatat_res:
                orig_path = pathlib.Path(newfstatat_res.group('cwd')) / newfstatat_res.group('path')
                fd = newfstatat_res.group('open_fd')

                timestamp = float(rest_of_line.split(' ', maxsplit=1)[0])
                stat_file = tracer.StatFile(pathlib.Path(newfstatat_res.group('cwd')), orig_path, fd, timestamp)
                trace_processes[pid].add_statted_file(stat_file)
            elif debug:
                print('newfstatat failed:', line, file=sys.stderr)
        elif syscall in ['write', 'pwrite64']:
            if syscall == 'write':
                if is_resumed:
                    continue
                write_res = syscalls.write_re.search(line)
            else:
                write_res = syscalls.pwrite64_re.search(line)
            if write_res:
                # extra sanity check to see if data was written
                try:
                    num_bytes = int(line.strip().rsplit('=')[-1])
                except:
                    continue
                # store the path of the file that was written to, except
                # if it is a pipe
                write_path = write_res.group('path')
                if not write_path.startswith('pipe:['):
                    trace_processes[pid].add_written_file(write_path)
                else:
                    # fd related to the pipe is an output
                    pass
            elif debug:
                print('write/pwrite64 failed:', line, file=sys.stderr)
        elif syscall in ['rename', 'renameat2']:
            # renaming is important to track.
            # Example: in the Linux kernel the file include/config/auto.conf
            # is "created" by renaming an already existing file.
            if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                continue
            if syscall == 'rename':
                rename_res = syscalls.rename_re.search(rest_of_line)
            else:
                rename_res = syscalls.renameat2_re.search(rest_of_line)
            if rename_res:
                timestamp = float(rest_of_line.split(' ', maxsplit=1)[0])
                if syscall == 'rename':
                    original_name = pathlib.Path(rename_res.group('original'))
                    original_cwd = cwd
                    renamed_name = pathlib.Path(rename_res.group('renamed'))
                    renamed_cwd = cwd
                elif syscall == 'renameat2':
                    original_name = pathlib.Path(rename_res.group('original'))
                    original_cwd = pathlib.Path(rename_res.group('cwd'))
                    renamed_name = pathlib.Path(rename_res.group('renamed'))
                    renamed_cwd = pathlib.Path(rename_res.group('cwd2'))
                renamed_file = tracer.RenamedFile(timestamp, original_name, original_cwd,
                                                  renamed_name, renamed_cwd)
                trace_processes[pid].add_renamed_file(renamed_file)


    # Finally write meta results to JSON
    meta = {'buildid': buildid, 'root': root_pid, 'basepath': str(basepath), 'output': 'pickle'}

    with open(output_directory / "meta.json", encoding='utf-8', mode='w') as outfile:
        json.dump(meta, outfile, indent=4)

    if debug:
        print("END RECONSTRUCTION", datetime.datetime.now(datetime.UTC).isoformat(), file=sys.stderr)

def get_files(pickle_directory, debug=False):
    '''Helper method to determine opened/created/statted
       files given a result pickle.'''
    if debug:
        now = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"{now} - Started reading trace data from {pickle_directory}", file=sys.stderr)

    inputs = set()
    outputs = set()
    statted = set()

    opened_files = set()
    renamed_files = set()
    renamed_to_orig = {}

    # load the data, starting with the top level meta file
    with open(pickle_directory / 'meta.json', 'r', encoding='utf-8') as meta_file:
        meta = json.load(meta_file)

    pid_deque = collections.deque()
    pid_deque.append(meta['root'])

    basepath = pathlib.Path(meta['basepath'])

    # load the first pickle and then recurse
    while True:
        try:
            pid = pid_deque.popleft()
            with open(pickle_directory / f"{pid}.pickle", 'rb') as infile:
                data = pickle.load(infile)
                pid_deque.extend(data.children)
                for opened_file in data.opened_files:
                    if opened_file.is_directory:
                        # directories can be safely skipped
                        continue

                    if opened_file.resolved_path == basepath:
                        continue

                    # TODO: also check for the original name,
                    # not just the fully resolved path
                    if opened_file.resolved_path in renamed_to_orig:
                        opened_path = renamed_to_orig[opened_file.resolved_path]
                    else:
                        opened_path = opened_file.resolved_path
                    if opened_file.is_read:
                        inputs.add(opened_path)
                    if opened_file.is_written:
                        outputs.add(opened_path)

                for opened_file in data.statted_files:
                    statted.add(opened_file.original_path)

                for opened_file in data.renamed_files:
                    renamed_files.add(opened_file)
                    renamed_to_orig[opened_file.renamed_cwd / opened_file.renamed_name] = opened_file.original_cwd / opened_file.original_name
        except IndexError:
            break

    if debug:
        now = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"{now} - Finished reading trace data from {pickle_directory}", file=sys.stderr)

    if debug:
        now = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"{now} - Finished opened renamed", file=sys.stderr)

    source_files = []
    system_files = []
    for input_file in sorted(inputs.difference(outputs)):
        if input_file.is_relative_to('/proc'):
            continue
        if input_file.is_relative_to('/dev'):
            continue
        if input_file == meta['basepath']:
            # do not include the base directory
            continue

        # now split into "source files" (part of the source code of the build)
        # and "systen files" (already installed files on the system, or temporary
        # files written during the build)
        if input_file.is_relative_to(meta['basepath']):
            source_files.append(input_file)
        else:
            system_files.append(input_file)

    if debug:
        now = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"{now} - Finished opened splitting", file=sys.stderr)

    source_files_statted = []
    system_files_statted = []

    for input_file in sorted(statted):
        if input_file.is_relative_to('/proc'):
            continue
        if input_file.is_relative_to('/dev'):
            continue
        if input_file == meta['basepath']:
            # do not include the base directory
            continue
        if input_file in inputs:
            # do not include files that are opened
            continue
        if input_file in outputs:
            # do not include files that are written to
            continue

        # now split into "source files" (part of the source code of the build)
        # and "systen files" (already installed files on the system, or temporary
        # files written during the build)
        if input_file.is_relative_to(meta['basepath']):
            source_files_statted.append(input_file)
        else:
            system_files_statted.append(input_file)

    if debug:
        now = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"{now} - Finished stat'ed splitting", file=sys.stderr)

    return (meta, source_files, system_files, renamed_files, source_files_statted)

def get_processes(pickle_directory, debug=False):
    '''Helper method to return a processes object that can be turned into a graph'''
    if debug:
        now = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"{now} - Started reading trace data from {pickle_directory}", file=sys.stderr)

    # store which children create which processes
    pid_to_children = {}
    pid_to_command = {}

    # load the data, starting with the top level meta file
    with open(pickle_directory / 'meta.json', 'r', encoding='utf-8') as meta_file:
        meta = json.load(meta_file)

    pid_deque = collections.deque()
    pid_deque.append(meta['root'])

    basepath = pathlib.Path(meta['basepath'])

    # load the first pickle and then recurse
    while True:
        try:
            pid = pid_deque.popleft()
            with open(pickle_directory / f"{pid}.pickle", 'rb') as infile:
                data = pickle.load(infile)
                pid_deque.extend(data.children)
                pid_to_children[pid] = data.children
                pid_to_command[pid] = data.command
        except IndexError:
            break

    if debug:
        now = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"{now} - Finished reading trace data from {pickle_directory}", file=sys.stderr)
    return pid_to_children, pid_to_command

@app.command(short_help='Create process creation graph')
@click.option('--pickle-dir', '-p', 'pickle_directory', required=True,
              help='name of directory with pickle files', type=click.Path(path_type=pathlib.Path))
@click.option('--output-format', 'output_format', required=True,
              help='output format', type=click.Choice(['graphviz', 'json', 'text', 'yaml']))
@click.option('--output-file', 'output_file', required=True,
              help='output file (don\'t use an extension!)',
              type=click.Path(path_type=pathlib.Path))
@click.option('--alt-root', help='alternative root PID')
@click.option('--debug', '-d', is_flag=True, help='print debug information')
def create_process_graph(pickle_directory, output_format, output_file, alt_root, debug):
    '''Create a process graph'''
    meta_file = pathlib.Path(pickle_directory / 'meta.json')
    if not meta_file.exists():
        raise click.ClickException(f"{meta_file} does not exist")

    with open(pickle_directory / 'meta.json', 'r', encoding='utf-8') as meta_file:
        meta = json.load(meta_file)

    pid_to_children, pid_to_command = get_processes(pickle_directory, debug)

    # walk the children, starting with the root process
    pid_deque = collections.deque()

    if alt_root:
        pid = alt_root
    else:
        pid = meta['root']

    pid_deque.append(pid)

    # create an initial graph if graphviz is the output format
    if output_format == 'graphviz':
        output_graph = graphviz.Digraph()
        output_graph.attr(rankdir='LR')
        cmd = f"PID: {pid}\n{pid_to_command[pid]['command']}"
        output_graph.node(pid, cmd)
    elif output_format in ['json', 'yaml']:
        opened_file = open(output_file, encoding='utf-8', mode='w')
        output_graph = {'root': pid, 'nodes': []}
    elif output_format == 'text':
        opened_file = open(output_file, encoding='utf-8', mode='w')

    while True:
        try:
            pid = pid_deque.popleft()
            if output_format in ['json', 'yaml']:
                command = pid_to_command[pid]['command']
                args = pid_to_command[pid]['args']
                node = {'pid': pid, 'creates': [], 'command': command, 'args': args}
            elif output_format == 'text':
                if pid_to_command[pid]['args']:
                    cmd = f"{pid_to_command[pid]['command']} {pid_to_command[pid]['args']}"
                else:
                    cmd = f"{pid_to_command[pid]['command']}"

            if pid_to_children[pid]:
                if output_format == 'graphviz':
                    for child in pid_to_children[pid]:
                        child_cmd = f"PID: {child}\n{pid_to_command[child]['command']}"
                        output_graph.node(child, child_cmd)
                        output_graph.edge(pid, child)
                elif output_format in ['json', 'yaml']:
                    command = pid_to_command[pid]['command']
                    args = pid_to_command[pid]['args']
                    node = {'pid': pid, 'creates': [], 'command': command, 'args': args}
                    for child in pid_to_children[pid]:
                        create = {'pid': child}
                        node['creates'].append(create)
                elif output_format == 'text':
                    print(f"PID {pid} COMMAND {cmd} CREATES {pid_to_children[pid]}", file=opened_file)
                pid_deque.extend(pid_to_children[pid])
            else:
                if output_format == 'text':
                    print(f"PID {pid} COMMAND {cmd}", file=opened_file)

            if output_format in ['json', 'yaml']:
                output_graph['nodes'].append(node)

        except IndexError:
            break

    if output_format == 'graphviz':
        output_graph.format = 'png'
        output_graph.render(filename=output_file)
    elif output_format == 'json':
        # dump JSON
        json.dump(output_graph, opened_file, indent=2)
        opened_file.close()
    elif output_format == 'text':
        opened_file.close()
    elif output_format == 'yaml':
        # dump yaml
        yaml.dump(output_graph, opened_file)
        opened_file.close()


@app.command(short_help='Print all opened files')
@click.option('--pickle-dir', '-p', 'pickle_directory', required=True,
              help='name of directory with pickle files', type=click.Path(path_type=pathlib.Path))
@click.option('--output-format', 'output_format', required=True,
              help='output format', type=click.Choice(['json', 'text']))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
def print_open_files(pickle_directory, output_format, debug):
    '''Print all files that were opened during a build.'''
    meta_file = pathlib.Path(pickle_directory / 'meta.json')
    if not meta_file.exists():
        raise click.ClickException(f"{meta_file} does not exist")

    meta, source_files, system_files, renamed_files, source_files_statted = get_files(pickle_directory, debug)

    if output_format == 'text':
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
    elif output_format == 'json':
        json_out = {}
        if system_files:
            json_out['system'] = list(map(lambda x: str(x), system_files))
        if source_files:
            json_out['source'] = list(map(lambda x: str(x.relative_to(meta['basepath'])), source_files))
        print(json.dumps(json_out, indent=4))

@app.command(short_help='Copy source code files')
@click.option('--pickle', '-p', 'pickle_directory', required=True,
              help='name of directory with pickle files', type=click.Path(path_type=pathlib.Path))
@click.option('--source-directory', '-i', 'source_directory', required=True,
              help='source directory', type=click.Path(path_type=pathlib.Path))
@click.option('--output-directory', '-o', 'output_directory', required=True,
              help='output directory', type=click.Path(path_type=pathlib.Path))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
@click.option('--ignore-stat', is_flag=True, help='ignore files that are merely stat\'ed')
@click.option('--ignore-not-found', is_flag=True, help='ignore file not found errors')
def copy_files(pickle_directory, source_directory, output_directory, ignore_stat,
               ignore_not_found, debug):
    '''Copy all files that were opened during a build.'''
    # directory with original source code files
    if not source_directory.is_dir():
        raise click.ClickException(f"{source_directory} does not exist or is not a directory")

    # directory where files should be copied to
    try:
        if output_directory.exists():
            raise click.ClickException(f"{output_directory} already exists")
    except PermissionError as e:
        raise click.ClickException(f"Permission error for {output_directory}") from e

    try:
        output_directory.mkdir()
    except Exception as e:
        raise click.ClickException(f"Could not create {output_directory}") from e

    meta_file = pathlib.Path(pickle_directory / 'meta.json')
    if not meta_file.exists():
        raise click.ClickException(f"{meta_file} does not exist")

    meta, source_files, system_files, renamed_files, source_files_statted = get_files(pickle_directory, debug)

    files_to_copy = []

    # Ignoring files that are merely stat'ed can indicate issues
    # in the build process, like files being unnecessarily needed
    # (but not actually used) during the build.
    if not ignore_stat:
        for input_file in source_files_statted:
            source_file = input_file.relative_to(meta['basepath'])
            copy_path = source_directory / source_file
            if not copy_path.exists():
                continue
            if not copy_path.is_file():
                continue
            destination = output_directory / source_file

            files_to_copy.append((copy_path, destination))

    # Gather all the file paths that were actually opened.
    for input_file in source_files:
        source_file = input_file.relative_to(meta['basepath'])
        copy_path = source_directory / source_file
        if not copy_path.exists():
            if ignore_not_found:
                print(f"Warning: expected path {copy_path} does not exist.", file=sys.stderr)
                continue
            print(f"Expected path {copy_path} does not exist, exiting...", file=sys.stderr)
            sys.exit()

        if not copy_path.is_file():
            continue

        destination = output_directory / source_file

        if debug:
            print(f"adding {copy_path} to files_to_copy", file=sys.stderr)
        files_to_copy.append((copy_path, destination))

    # Copy all the files that should be copied to the output directory,
    # including the full subdirectory name.
    for source_file, destination in files_to_copy:
        # first make sure the subdirectory exists
        if source_file.parent != '.':
            destination.parent.mkdir(parents=True, exist_ok=True)

        # TODO: symlinks
        if debug:
            print(f"copying {source_file}", file=sys.stderr)
        shutil.copy(source_file, destination)


@app.command(short_help='Search a file in the output and report all relevant process ids')
@click.option('--path', '-f', 'searchpath', type=click.Path(path_type=pathlib.Path),
              help='path to be searched', required=True)
@click.option('--pickle-dir', '-p', 'pickle_directory', required=True,
              help='name of directory with pickle files', type=click.Path(path_type=pathlib.Path))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
def search_path(pickle_directory, debug, searchpath):
    '''Search a file in the output and report all relevant process ids.'''
    meta_file = pathlib.Path(pickle_directory / 'meta.json')
    if not meta_file.exists():
        raise click.ClickException(f"{meta_file} does not exist")

    meta, source_files, system_files, renamed_files, source_files_statted = get_files(pickle_directory, debug)

def single_tracefile(tracefile_root, pid, parent, cwd, command, output_directory, debug):
    '''Process a single trace file. Recurse into trace files of child processes.'''
    # Create the trace process object and associate the
    # PID and a fictional parent with it.
    if not parent == '':
        parent_pid = 'root'
    else:
        parent_pid = parent.pid

    # create the TraceProcess object for the process
    trace_process = tracer.TraceProcess(pid, parent_pid)
    tracefile = tracefile_root.with_suffix(f'.{pid}')

    # local information
    children_pids = []

    # Store if files were (successfully) opened, renamed, statted or written/created.
    # These collections could overlap.
    opened = []
    renamed = []
    statted = []

    # Store files that were opened by child processes
    opened_by_child_processes = []

    closed = set()
    read = set()
    written = set()

    # Keep bidirectional state for pipes for a single process
    fds_to_pipe = {}
    pipe_to_fds = {}

    # Keep state for all opened files. This is stored as part
    # of the process and updated every time the process is updated.
    open_fds = {}

    # Store the file descriptors for all opened
    # files inherited from the parent process.
    if parent:
        for opened_file in parent.open_fds:
            open_fds[opened_file.fd] = copy.copy(opened_file)

    # Copy any pipe information from the parent process

    with open(tracefile, encoding='utf-8', mode='r') as file_to_process:
        for line in file_to_process:
            # Skip lines that do not contain tracing information
            if '=' not in line:
                continue

            # Grab the name of the system call.
            syscall_result = syscalls.syscall_re.match(line)
            if not syscall_result:
                continue

            syscall = syscall_result.group('syscall')

            # Skip uninteresting system calls
            if syscall in IGNORE_SYSCALLS:
                continue

            if debug:
                print(trace_process.pid, syscall, file=sys.stderr)

            # Then process the interesting system calls.
            if syscall in ['chdir', 'fchdir']:
                if not line.rsplit('=', maxsplit=1)[1].strip().startswith('0'):
                    continue
                if syscall == 'chdir':
                    chdir_res = syscalls.chdir_re.search(line)
                elif syscall == 'fchdir':
                    chdir_res = syscalls.fchdir_re.search(line)
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
                elif debug:
                    print('chdir/fchdir failed:', line, file=sys.stderr)
            elif syscall in ['clone', 'clone3', 'vfork']:
                if syscall == 'clone':
                    cloneres = syscalls.clone_re.search(line)
                elif syscall == 'clone3':
                    cloneres = syscalls.clone3_re.search(line)
                elif syscall == 'vfork':
                    cloneres = syscalls.vfork_re.search(line)
                if not cloneres:
                    if debug:
                        print('clone/clone3/vfork failed:', line, file=sys.stderr)
                    continue

                # the PID of the cloned process
                clone_pid = cloneres.group('clone_pid')

                # store the command of the cloned process. This is often also
                # available in the child process via getpid() and then frequently
                # overwritten by execve, but sometimes neither is used and then
                # it is hard to guess from the child process what the command
                # actually was.
                clone_command = {'command': cloneres.group('command'), 'args': None}

                flags = []
                if syscall != 'vfork':
                    flags = cloneres.group('flags')

                # Add the child PID to the children PIDs for the process.
                children_pids.append(clone_pid)

                # Create a trace process and process trace file for the child process.
                single_tracefile(tracefile_root, clone_pid, trace_process, cwd,
                                         clone_command, output_directory, debug)

            elif syscall == 'close':
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                close_res = syscalls.close_re.search(line)
                if not close_res:
                    if debug:
                        print('close failed:', line, file=sys.stderr)
                    continue
                closed.add(close_res.group('path'))
                fd = close_res.group('fd')
                try:
                    del open_fds[fd]
                except:
                    pass

                if 'pipe:[' in close_res.group('path'):
                    # Remove any file descriptors associated with pipes.
                    try:
                        del fds_to_pipe[fd]
                    except KeyError:
                        pass

                    try:
                        pipe_nr = close_res.group('path').split('[')[1][:-1]
                        read_fd = pipe_to_fds[pipe_nr].get('read', None)
                        write_fd = pipe_to_fds[pipe_nr].get('write', None)
                        if read_fd == fd:
                            del pipe_to_fds[pipe_nr]['read']
                        elif write_fd == fd:
                            del pipe_to_fds[pipe_nr]['write']

                        # check if pipe_to_fds[pine_nr] is empty and
                        # delete if so.
                        if not pipe_to_fds[pipe_nr]:
                            del pipe_to_fds[pipe_nr]
                    except KeyError:
                        pass
                    trace_process.fds_to_pipe = copy.copy(fds_to_pipe)
                    trace_process.pipe_to_fds = copy.copy(pipe_to_fds)
                trace_process.open_fds = list(open_fds.values())
            elif syscall == 'dup2':
                dup2_res = syscalls.dup2_re.search(line)
                if not dup2_res:
                    continue

                old_fd = dup2_res.group('old_fd')
                new_fd = dup2_res.group('new_fd')

                # TODO: is this actually correct?
                if old_fd in open_fds:
                    new_file = copy.deepcopy(open_fds[old_fd])
                    new_file.fd = new_fd
                    open_fds[new_fd] = new_file
                trace_process.open_fds = list(open_fds.values())
                if 'pipe:[' in dup2_res.group('old_fd_resolved') or 'pipe:[' in dup2_res.group('new_fd_resolved'):
                    pass
            elif syscall == 'execve':
                # store the programs that are (successfully) executed
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                execveres = syscalls.execve_re.search(line)
                if execveres:
                    command = {'command': execveres.group('command'), 'args': execveres.group('args')}
                elif debug:
                    print('execve failed:', line, file=sys.stderr)
            elif syscall == 'getcwd':
                getcwd_result = syscalls.getcwd_re.search(line)
                if getcwd_result:
                    cwd = pathlib.Path(os.path.normpath(getcwd_result.group('cwd')))
                elif debug:
                    print('getcwd failed:', line, file=sys.stderr)
            elif syscall == 'getpid':
                # create a placeholder for commands. This value is typically
                # overwritten when parsing execve
                getpid_results = syscalls.getpid_re.search(line)
                if getpid_results:
                    command = {'command': getpid_results.groups()[0], 'args': None}
                elif debug:
                    print('getpid failed:', line, file=sys.stderr)
            elif syscall == 'newfstatat':
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                newfstatat_res = syscalls.newfstatat_re.search(line)
                if newfstatat_res:
                    orig_path = pathlib.Path(newfstatat_res.group('cwd')) / newfstatat_res.group('path')
                    fd = newfstatat_res.group('open_fd')

                    timestamp = float(line.split(' ', maxsplit=1)[0])
                    stat_file = tracer.StatFile(pathlib.Path(newfstatat_res.group('cwd')), orig_path, fd, timestamp)
                    statted.append(stat_file)
                elif debug:
                    print('newfstatat failed:', line, file=sys.stderr)
            elif syscall in ['openat']:
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                openres = syscalls.openat_re.search(line)
                if openres:
                    # Store both the (resolved) original path
                    # and the fully resolved path (related to symbolic links).
                    # This include all files that are opened, including in
                    # places such as /dev and /proc which are defined in IGNORE_DIRECTORIES.
                    orig_path = pathlib.Path(openres.group('cwd')) / openres.group('path')
                    resolved_path = pathlib.Path(openres.group('resolved_path'))
                    flags = openres.group('flags').split('|')
                    fd = openres.group('result_fd')

                    if debug:
                        print(f"PROCESS {trace_process.pid} OPENED {resolved_path}",
                              file=sys.stderr)

                    already_opened = False
                    for o in opened:
                        if o.original_path == orig_path:
                            already_opened = True
                            break
                    if not already_opened:
                        timestamp = float(line.split(' ', maxsplit=1)[0])
                        opened_file = tracer.OpenedFile(pathlib.Path(openres.group('cwd')), flags, orig_path, resolved_path, fd, timestamp)
                        opened.append(opened_file)
                        open_fds[fd] = opened_file
                    trace_process.open_fds = list(open_fds.values())
                elif debug:
                    print('openat failed:', line, file=sys.stderr)
            elif syscall in ['pipe2']:
                # Extract file descriptor numbers and pipe number
                # man 7 pipe
                pipe_res = syscalls.pipe2_re.search(line)
                if pipe_res:
                    # each pipe has a read and write file descriptor associated with it
                    read_fd = pipe_res.group('read_fd')
                    write_fd = pipe_res.group('write_fd')

                    # in the strace output there are two values for the pipe
                    # namely the read end and the write end. These are always
                    # identical, but extracted for completeness sake.
                    read_pipe = pipe_res.group('read_pipe')
                    write_pipe = pipe_res.group('write_pipe')

                    # store the file descriptor/pipe mappings
                    fds_to_pipe[read_fd] = read_pipe
                    fds_to_pipe[write_fd] = read_pipe
                    pipe_to_fds[read_pipe] = {'read': read_fd, 'write': write_fd}
                    if write_fd in open_fds:
                        open_fds[read_fd] = copy.deepcopy(open_fds[write_fd])
                    trace_process.open_fds = list(open_fds.values())
                    trace_process.fds_to_pipe = copy.copy(fds_to_pipe)
                    trace_process.pipe_to_fds = copy.copy(pipe_to_fds)
                elif debug:
                    print('pipe2 failed:', line, file=sys.stderr)
            elif syscall in ['read', 'pread64']:
                if syscall == 'read':
                    read_res = syscalls.read_re.search(line)
                elif syscall == 'pread64':
                    read_res = syscalls.pread64_re.search(line)

                if read_res:
                    # store the path of the file that was read from, except
                    # if it is a pipe
                    read_path = read_res.group('path')
                    if not read_path.startswith('pipe:['):
                        read.add(read_path)
                    else:
                        # fd related to the pipe is an input
                        pass
                elif debug:
                    print('read/pread64 failed:', line, file=sys.stderr)
            elif syscall in ['rename', 'renameat2']:
                # renaming is important to track.
                # Example: in the Linux kernel the file include/config/auto.conf
                # is "created" by renaming an already existing file.
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                if syscall == 'rename':
                    rename_res = syscalls.rename_re.search(line)
                else:
                    rename_res = syscalls.renameat2_re.search(line)
                if rename_res:
                    timestamp = float(line.split(' ', maxsplit=1)[0])
                    if syscall == 'rename':
                        original_name = pathlib.Path(rename_res.group('original'))
                        original_cwd = cwd
                        renamed_name = pathlib.Path(rename_res.group('renamed'))
                        renamed_cwd = cwd
                    elif syscall == 'renameat2':
                        original_name = pathlib.Path(rename_res.group('original'))
                        original_cwd = pathlib.Path(rename_res.group('cwd'))
                        renamed_name = pathlib.Path(rename_res.group('renamed'))
                        renamed_cwd = pathlib.Path(rename_res.group('cwd2'))
                    renamed_file = tracer.RenamedFile(timestamp, original_name, original_cwd,
                                                      renamed_name, renamed_cwd)
                    renamed.append(renamed_file)
                elif debug:
                    print('rename/renameat failed:', line, file=sys.stderr)
            elif syscall in ['symlinkat']:
                if line.rsplit('=', maxsplit=1)[1].strip().startswith('-1'):
                    continue
                if syscall == 'symlinkat':
                    symlink_res = syscalls.symlinkat_re.search(line)
                if symlink_res:
                    timestamp = float(line.split(' ', maxsplit=1)[0])
                    if syscall == 'symlinkat':
                        target = pathlib.Path(symlink_res.group('target'))
                        linkpath = pathlib.Path(symlink_res.group('linkpath'))
                elif debug:
                    print('symlinkat failed:', line, file=sys.stderr)
            elif syscall in ['write', 'pwrite64']:
                if syscall == 'write':
                    write_res = syscalls.write_re.search(line)
                else:
                    write_res = syscalls.pwrite64_re.search(line)
                if write_res:
                    # extra sanity check to see if data was written
                    try:
                        num_bytes = int(line.strip().rsplit('=')[-1])
                    except:
                        continue
                    # store the path of the file that was written to, except
                    # if it is a pipe
                    write_path = write_res.group('path')
                    if not write_path.startswith('pipe:['):
                        written.add(write_path)
                    else:
                        # fd related to the pipe is an output
                        pass
                elif debug:
                    print('write/pwrite64 failed:', line, file=sys.stderr)

    # store the results for the trace process
    trace_process.children = children_pids
    trace_process.opened_files = opened
    trace_process.renamed_files = renamed
    trace_process.statted_files = statted
    trace_process.fds_to_pipe = fds_to_pipe
    trace_process.pipe_to_fds = pipe_to_fds
    trace_process.read_files = sorted(read)
    trace_process.written_files = sorted(written)
    trace_process.command = command

    # write the results to a pickle
    with open(output_directory / f"{trace_process.pid}.pickle", 'wb') as outfile:
        pickle.dump(trace_process, outfile)

if __name__ == "__main__":
    app()
