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

    @property
    def statted_files(self):
        return self._statted_files

    @statted_files.setter
    def statted_files(self, statted_files):
        self._statted_files = statted_files
