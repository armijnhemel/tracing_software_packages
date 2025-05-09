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
