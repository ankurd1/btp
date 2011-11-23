#!/usr/bin/python

from cmd import Cmd
import subprocess
import pexpect
import os
import logging
import time

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
        self.qemu_cwd = None

    def read_init_file(self, filename):
        f = open(filename, 'r')
        for line in f:
            self.onecmd(line)
        
        logging.info('Init file loaded.')

    def do_EOF(self, line):
        '''Kill qemu and gdb and exit.'''
        if (self.gdb_pexpect is not None):
            self.gdb_pexpect.kill(0)
        if (self.qemu_process is not None):
            self.qemu_process.kill()
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

    def do_set_qemu_cwd(self, line):
        '''Specify cwd for qemu.'''
        self.qemu_cwd = line

    def do_set_replay_file(self, line):
        '''Specify the replay file.'''
        self.qemu_replay_file = line

    def do_set_image(self, line):
        '''Specify the qcow2 image file.'''
        self.image = line

    def do_start(self, line):
        '''Start qemu and attach gdb to it.'''
        if (self.qemu_process is not None and self.qemu_process.poll() is None):
            self.qemu_process.kill()

        cmd_line = [self.qemu_exec]
        cmd_line.extend(self.qemu_args)
        cmd_line.extend([self.qemu_replay_keyword, self.qemu_replay_file,
            self.image])

        logging.debug("qemu cmd_line = " + " ".join(cmd_line))
        self.qemu_process = subprocess.Popen(cmd_line, cwd=self.qemu_cwd,
                stdout = subprocess.PIPE, stdin = subprocess.PIPE,
                stderr = subprocess.PIPE)

        time.sleep(5)
        #logging.debug(self.qemu_process.stdout.read())
        
        if (self.gdb_pexpect is None):
            self.gdb_pexpect = pexpect.spawn(self.gdb_exec)
            self.gdb_pexpect.expect('\(gdb\)')

        #self.gdb_pexpect.interact()
        self.gdb_pexpect.sendline(self.gdb_connect_cmd)
        self.gdb_pexpect.expect('\(gdb\)')

        logging.debug(self.gdb_pexpect.before)
        
        #self.gdb_pexpect.interact()
        self.gdb_pexpect.sendline('file ' + self.vmlinux)
        self.gdb_pexpect.expect('y or n')
        self.gdb_pexpect.sendline('y')
        self.gdb_pexpect.expect('\(gdb\)')
        logging.debug(self.gdb_pexpect.before)

    def do_watch(self, line):
        '''watch [var_name]
        Watch the specified kernel variable.'''

        self.gdb_pexpect.sendline('watch ' + line)
        self.gdb_pexpect.expect('\(gdb\)')
        #logging.debug(self.gdb_expect.before)

    def do_run_till_live(self, line):
        pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    dbg = RrDebugger()
    if os.path.exists('.rrdebuginit'):
        dbg.read_init_file('.rrdebuginit')
    dbg.cmdloop()
