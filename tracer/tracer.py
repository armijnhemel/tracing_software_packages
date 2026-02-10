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
        '''Return the current working directory'''
        return self._cwd

    @property
    def fd(self):
        '''Return the file descriptor of the opened file'''
        return self._fd

    @fd.setter
    def fd(self, fd):
        '''Set the file descriptor of the opened file'''
        self._fd = fd

    @property
    def flags(self):
        '''Return the flags used for open() or openat()'''
        return self._flags

    @property
    def original_path(self):
        '''Return the original path as used in open() or openat()'''
        return self._original_path

    @property
    def resolved_path(self):
        '''Return the resolved, cleaned up, path used in open() or openat()'''
        return self._resolved_path

    @property
    def timestamp(self):
        '''Return the timestamp of the open() or openat() call'''
        return self._timestamp

    @property
    def is_directory(self):
        '''Return if the path is opened as a directory'''
        return 'O_DIRECTORY' in self.flags

    @property
    def is_created(self):
        '''Return if the path is created (opened with O_CREAT)'''
        return 'O_CREAT' in self.flags

    @property
    def is_read(self):
        '''Return if the path is read (opened with read flags)'''
        is_read = False
        if 'O_RDONLY' in self.flags or 'O_RDWR' in self.flags:
            is_read = True
        return is_read

    @property
    def is_read_only(self):
        '''Return if the path is opened as read only'''
        return 'O_RDONLY' in self.flags

    @property
    def is_truncated(self):
        '''Return if the file is truncated (in combination with writing)'''
        return 'O_TRUNC' in self.flags

    @property
    def is_written(self):
        '''Return if the path is written to (opened with write flags)'''
        is_write = False
        if 'O_WRONLY' in self.flags or 'O_RDWR' in self.flags:
            is_write = True
        return is_write


class RenamedFile:
    def __init__(self, timestamp, original_name, original_cwd, renamed_name, renamed_cwd):
        self._timestamp = timestamp
        self._original_name = original_name
        self._original_cwd = original_cwd
        self._renamed_name = renamed_name
        self._renamed_cwd = renamed_cwd

    @property
    def timestamp(self):
        '''Return the timestamp of the rename() or renameat2() call'''
        return self._timestamp

    @property
    def original_name(self):
        '''Return the original name of the file'''
        return self._original_name

    @property
    def original_cwd(self):
        '''Return the original current working directory of the file'''
        return self._original_cwd

    @property
    def renamed_name(self):
        '''Return the renamed name of the file'''
        return self._renamed_name

    @property
    def renamed_cwd(self):
        '''Return the renamed current working directory of the file'''
        return self._renamed_cwd


class StatFile:
    '''Helper class to store information about a file queried by stat.'''
    def __init__(self, cwd, original_path, fd, timestamp):
        self._cwd = cwd
        self._original_path = original_path
        self._fd = fd
        self._timestamp = timestamp

    @property
    def cwd(self):
        '''Return the current working directory'''
        return self._cwd

    @property
    def fd(self):
        '''Return the file descriptor of the opened file'''
        return self._fd

    @fd.setter
    def fd(self, fd):
        '''Set the file descriptor of the opened file'''
        self._fd = fd

    @property
    def original_path(self):
        '''Return the original path as used in stat() or newfstatat()'''
        return self._original_path

    @property
    def resolved_path(self):
        '''Return the resolved, cleaned up, path used in stat() or newfstatat()'''
        return self._resolved_path

    @property
    def timestamp(self):
        '''Return the timestamp of the stat() or newfstatat() call'''
        return self._timestamp


class TraceProcess:
    '''Helper class to store information about a single process.
       At the end of trace processing this object should contain
       the entire state of the process.'''
    def __init__(self, pid, parent_pid):
        '''Initialization method for the class, sets several
           variables to default values.'''
        # The original parent PID
        self._parent_pid = parent_pid

        # The original PID
        self._pid = pid

        # Files that were opened by this process (entire lifetime)
        self._opened_files = []

        # Files that were renamed by this process (entire lifetime)
        self._renamed_files = []

        # Files that were renamed by this process (entire lifetime)
        self._statted_files = []
        self._children = []

        # The shell command associated with the process
        self._command = None

    @property
    def parent_pid(self):
        '''Return the process id of the parent process'''
        return self._parent_pid

    @property
    def pid(self):
        '''Return the process id of this process'''
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

    @property
    def statted_files(self):
        return self._statted_files

    @statted_files.setter
    def statted_files(self, statted_files):
        self._statted_files = statted_files
