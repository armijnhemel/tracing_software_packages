class StatFile:
    '''Helper class to store information about a file queried by stat.'''
    def __init__(self, cwd, original_path, fd, timestamp):
        self._cwd = cwd
        self._original_path = original_path
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
    def original_path(self):
        return self._original_path

    @property
    def resolved_path(self):
        return self._resolved_path

    @property
    def timestamp(self):
        return self._timestamp
