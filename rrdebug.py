#!/usr/bin/python

from cmd import Cmd
import subprocess
import pexpect

class RrDebugger(Cmd):
    def __init__(self):
        Cmd.__init__(self)
        self.prompt = 'rr_dbg>'
        self.vmlinux = 'vmlinux'
        self.gdb_exec = 'gdb'
        self.qemu_exec = 'qemu'
        self.qemu_args = ['-s', '-no-reboot']
        self.qemu_replay_keyword = '-replay'
        self.qemu_replay_file = 'r.log'
        self.gdb_connect_cmd = 'target remote localhost:1234'
        self.image = None
        self.qemu_process = None
        self.gdb_pexpect = None

    def read_init_file(self, filename):
        f = open(filename, 'r')
        for line in f:
            self.onecmd(line)

    def do_EOF(self, line):
        return True

    def do_set_vmlinux(self, line):
        '''Specify the vmlinux file.'''
        self.vmlinux = line

    def do_set_gdb(self, line):
        '''Specify the path to gdb.'''
        self.gdb_exec = line

    def do_set_qemu(self, line):
        '''Specify the path to qemu and any additional arguments.'''
        line_split = line.split(" ")
        self.qemu_exec = line_split[0]
        if (len(line_split) > 1):
            self.qemu_args.extend(line_split[1:])

    def do_set_replay_file(self, line):
        '''Specify the replay file.'''
        self.qemu_replay_file = 'line'

    def do_set_image(self, line):
        '''Specify the qcow2 image file.'''
        self.image = line

    def do_start(self, line):
        '''Start qemu and attach gdb to it.'''
        if (self.qemu_process.poll() is None):
            self.qemu_process.kill()

        self.qemu_process = subprocess.Popen([qemu_exec].extend(qemu_args).\
                extend([qemu_replay_keyword, qemu_replay_file, image]),
                stdout = subprocess.PIPE, stdin = subprocess.PIPE,
                stderr = subprocess.PIPE)
        
        if (self.gdb_pexpect is None):
            self.gdb_pexpect = pexpect.spawn(self.gdb_exec)
            self.gdb_pexpect.expect('(gdb)')

        self.gdb_pexpect.sendline(self.gbd_connect_cmd)
        self.gdb_pexpect.expect('(gdb)')
        
        self.gdb_pexpect.sendline('file ' + self.vm_linux)
        self.gdb_pexpect.expect('(gdb)')

    def do_watch(self, line):
        '''watch [var_name]
        Watch the specified kernel variable.'''

        self.gdb_pexpect.sendline('watch ' + line)
        self.gdb_pexpect.expect('(gdb)')

    def do_run_till_live(self, line):
        pass


if __name__ == '__main__':
    dbg = RrDebugger()
    if os.path.exists('.rrdebuginit'):
        dbg.read_init_file('.rrdebuginit')
    dbg.cmdloop()
