class RenamedFile:
    def __init__(self, timestamp, original_name, original_cwd, renamed_name, renamed_cwd):
        self._timestamp = timestamp
        self._original_name = original_name
        self._original_cwd = original_cwd
        self._renamed_name = renamed_name
        self._renamed_cwd = renamed_cwd

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def original_name(self):
        return self._original_name

    @property
    def original_cwd(self):
        return self._original_cwd

    @property
    def renamed_name(self):
        return self._renamed_name

    @property
    def renamed_cwd(self):
        return self._renamed_cwd
