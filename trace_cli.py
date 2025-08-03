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
# Copyright 2017-2025 - Armijn Hemel

import collections
import copy
import datetime
import json
import os
import pathlib
import pickle
import re
import shutil
import sys

import click

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
@click.option('--tracefiles', '-f', 'tracefiles', required=True,
              help='path to trace files directory', type=click.Path(path_type=pathlib.Path))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
@click.option('--out', '-o', 'output_directory', required=True,
              help='name of output directory', type=click.Path(path_type=pathlib.Path))
def process_trace(basepath, buildid, tracefiles, output_directory, debug):
    '''Top level trace processor'''
    if not basepath.is_absolute():
        raise click.ClickException("--basepath should be an absolute path")

    # a directory with all the tracefiles
    if not (tracefiles.exists() and tracefiles.is_dir()):
        raise click.ClickException(f"{tracefiles} does not exist or is not a directory")

    if buildid.strip() == "":
        raise click.ClickException("build identifier empty")

    # directory where pickles should be written to
    try:
        if output_directory.exists():
            raise click.ClickException(f"{output_directory} already exists")
    except PermissionError as e:
        raise click.ClickException(f"Permission error for {output_directory}") from e

    try:
        output_directory.mkdir()
    except Exception as e:
        raise click.ClickException(f"Could not create {output_directory}") from e

    # Find the top level tracefile by looking at the first trace line of
    # every file, extracting the timestamp recorded and keeping track of the
    # earliest timestamp. The file with the earliest timestamp is the root
    # of the trace. Of course this will only work if the collection of trace
    # files is complete and the top level trace file is included as well.
    earliest = float('inf')
    for tracefile in tracefiles.glob('**/*'):
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

    cwd = ''

    # Create the trace process object and associate the
    # PID and a fictional parent with it.
    trace_process = tracer.TraceProcess(default_pid, 'root')

    # Process the first tracefile. This will process the other
    # dependent trace files recursively.
    process_single_tracefile(rootfile, trace_process, cwd, [], output_directory, debug)

    # Write meta results to JSON
    meta = {'buildid': buildid, 'root': default_pid, 'basepath': str(basepath)}

    with open(output_directory / "meta.json", 'w') as outfile:
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

@app.command(short_help='Print all opened files')
@click.option('--pickle-dir', '-p', 'pickle_directory', required=True,
              help='name of directory with pickle files', type=click.Path(path_type=pathlib.Path))
@click.option('--debug', '-d', is_flag=True, help='print debug information')
def print_open_files(pickle_directory, debug):
    '''Top level method to print all files that were opened during a build.'''
    meta_file = pathlib.Path(pickle_directory / 'meta.json')
    if not meta_file.exists():
        raise click.ClickException(f"{meta_file} does not exist")

    meta, source_files, system_files, renamed_files, source_files_statted = get_files(pickle_directory, debug)

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

    # in case there are multiple processes creating a file
    # pick the latest one.
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

def process_single_tracefile(tracefile, trace_process, cwd,
                             parent_opened, output_directory, debug):
    '''Process a single trace file. Recurse into trace files for dependent processes.'''
    # local information
    children_pids = []
    command = None
    closed = set()
    opened = []
    renamed = []
    statted = []

    # Keep state for pipes.
    fd_to_pipes = {}

    # Keep state for all opened files.
    open_fds = {}

    # Store the file descriptors for all opened
    # files inherited from the parent process.
    for opened_file in parent_opened:
        open_fds[opened_file.fd] = opened_file

    with open(tracefile, 'r') as file_to_process:
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

                flags = []
                if syscall != 'vfork':
                    flags = cloneres.group('flags')

                # Add the child PID to the children PIDs for the process.
                children_pids.append(clone_pid)

                # Cloned/forked processes inherit some information of the parent
                # process such as the current cwd as well as currently opened files.
                children_opened = open_fds.values()

                # Create a trace process and process trace file for the child process.
                child_trace_process = tracer.TraceProcess(clone_pid, trace_process.pid)
                child_tracefile = tracefile.with_suffix(f'.{clone_pid}')
                process_single_tracefile(child_tracefile, child_trace_process, cwd,
                                         children_opened, output_directory, debug)

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
                elif debug:
                    print('openat failed:', line, file=sys.stderr)
            elif syscall in ['pipe2']:
                # Correctly processing pipes is tricky.
                pipe_res = syscalls.pipe2_re.search(line)
                if pipe_res:
                    read_fd = pipe_res.group('read_fd')
                    write_fd = pipe_res.group('write_fd')
                    if write_fd in open_fds:
                        open_fds[read_fd] = copy.deepcopy(open_fds[write_fd])
                elif debug:
                    print('pipe2 failed:', line, file=sys.stderr)
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

    # store the results for the trace process
    trace_process.children = children_pids
    trace_process.opened_files = opened
    trace_process.renamed_files = renamed
    trace_process.statted_files = statted
    trace_process.command = command

    # write the results to a pickle
    with open(output_directory / f"{trace_process.pid}.pickle", 'wb') as outfile:
        pickle.dump(trace_process, outfile)

if __name__ == "__main__":
    app()
