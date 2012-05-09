import pexpect

class GdbPexpect():

    def __init__(self, gdb_exec):
        self.gdb_pexpect = pexpect.spawn(gdb_exec)
        self.gdb_pexpect.expect('\(gdb\)')

        # init
        self.execute('set pagination off')

    def execute(self, cmd, timeout=9999):
        self.gdb_pexpect.sendline(cmd)
        self.gdb_pexpect.expect('\(gdb\)', timeout)
        return self.gdb_pexpect.before.splitlines()
