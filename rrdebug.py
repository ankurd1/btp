#!/usr/bin/python

from cmd import Cmd
import subprocess
import pexpect
import os
import logging
import time
import argparse
import sys


class RrDebugger(Cmd):
    def __init__(self):
        Cmd.__init__(self)
        self.prompt = 'rr_dbg>'
        self.vmlinux = 'vmlinux'
        self.vmlinux_strip_prefix = ''
        self.gdb_exec = '/usr/bin/gdb'
        self.qemu_exec = 'qemu'
        self.qemu_args = ['-s', '-no-reboot']
        self.qemu_replay_keyword = '-replay'
        self.qemu_replay_file = 'r.log'
        self.gdb_connect_cmd = 'target remote localhost:1234'
        self.image = None
        self.qemu_process = None
        self.gdb_pexpect = None
        self.qemu_cwd = None
        self.executable = None
        self.gdb_macros = None
        self.executable_start_dump = None
        self.gdb_running = False
        self.setup_time = 8

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

    def do_set_gdb_macros(self, line):
        self.gdb_macros = line

    def do_set_vmlinux_strip_prefix(self, line):
        self.vmlinux_strip_prefix = line

    def gdb_execute(self, cmd, timeout=9999):
        self.gdb_pexpect.sendline(cmd)
        self.gdb_pexpect.expect('\(gdb\)', timeout)
        logging.debug(self.gdb_pexpect.before)
        return self.gdb_pexpect.before.splitlines()

    def get_start_dump(self, executable):
        gdb_new = pexpect.spawn(self.gdb_exec + ' ' + executable)
        gdb_new.expect('\(gdb\)')
        gdb_new.sendline('x/10x _start')
        gdb_new.expect('\(gdb\)')

        res = ""
        for lin in gdb_new.before.splitlines()[1:]:
            res += "".join(lin[lin.find(":") + 1:].strip().split())

        gdb_new.kill(0)
        return res

    def do_set_executable(self, line):
        self.executable = line
        self.executable_start_dump = self.get_start_dump(line)
        logging.debug("executable_start_dump =" + self.executable_start_dump)

    def do_set_gdb(self, line):
        '''Specify the path to gdb.'''
        self.gdb_exec = line

    def use_vmlinux(self):
        self.gdb_pexpect.sendline('file ' + self.vmlinux)
        self.gdb_pexpect.expect('y or n')
        self.gdb_pexpect.sendline('y')
        self.gdb_pexpect.expect('\(gdb\)')
        logging.debug(self.gdb_pexpect.before)

    def use_executable(self):
        self.gdb_pexpect.sendline('file ' + self.executable)
        self.gdb_pexpect.expect('y or n')
        self.gdb_pexpect.sendline('y')
        self.gdb_pexpect.expect('\(gdb\)')
        logging.debug(self.gdb_pexpect.before)

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

    def gdb_init(self):
        #TODO read these from init file
        self.gdb_execute('set pagination off')

    def do_setup(self, line):
        '''Start qemu and attach gdb to it.'''
        if (self.qemu_process is not None and\
                self.qemu_process.poll() is None):
            self.qemu_process.kill()

        cmd_line = [self.qemu_exec]
        cmd_line.extend(self.qemu_args)
        cmd_line.extend([self.qemu_replay_keyword, self.qemu_replay_file,
            self.image])

        logging.debug("qemu cmd_line = " + " ".join(cmd_line))
        null_file = open('/dev/null')
        self.qemu_process = subprocess.Popen(cmd_line, cwd=self.qemu_cwd,
                stdin=subprocess.PIPE,
                stderr=null_file)

        #return
        time.sleep(self.setup_time)
        #logging.debug(self.qemu_process.stdout.read())

        if (self.gdb_pexpect is None):
            self.gdb_pexpect = pexpect.spawn(self.gdb_exec)
            self.gdb_pexpect.expect('\(gdb\)')

        self.gdb_init()

        if (self.gdb_macros is not None):
            self.gdb_pexpect.sendline('source ' + self.gdb_macros)
            self.gdb_pexpect.expect('\(gdb\)')

        #self.gdb_pexpect.interact()
        self.gdb_pexpect.sendline(self.gdb_connect_cmd)
        self.gdb_pexpect.expect('\(gdb\)')

        logging.debug(self.gdb_pexpect.before)

        #self.gdb_pexpect.interact()

    def do_watchk(self, line):
        '''watch [var_name]
        Watch the specified kernel variable.'''

        self.use_vmlinux()
        self.gdb_pexpect.sendline('watch ' + line)
        self.gdb_pexpect.expect('\(gdb\)')
        #logging.debug(self.gdb_expect.before)

    def is_valid_exec_dump(self, dump):
        res = ""
        for lin in dump[1:]:
            res += "".join(lin[lin.find(":") + 1:].strip().split())

        return (res == self.executable_start_dump)

    def is_valid_bt(self, bt):
        for lin in bt[1:]:
            if (lin.find('??') > -1):
                return False
        return True

    def do_watchu(self, line):
        '''Watch [var_name]
        Watch the specified user variable.'''
        # First set a breakpoint at _start of the exec
        # Now when this bp is hit for the first time, set a wp on the req
        # var. Now, when this wp gets hit, see if bt is meaningful. If
        # yes, print it else ignore. Do this till either u go live or
        # you get another hit at _start.
        # Also, to count bp hit, compare the 50 bytes at _start in ram
        # to those in the exec (got from gdb initially).
        self.use_executable()
        self.gdb_execute('break _start')

        seen_bp = False
        while(True):
            hit = self.gdb_execute('c')
            if (hit[3].startswith('Breakpoint')):
                # bp hit, verify
                if (self.is_valid_exec_dump(self.gdb_execute('x/10x _start'))):
                    if seen_bp:
                        return
                    else:
                        seen_bp = True
                        self.gdb_execute('watch ' + line)
                continue

            if (hit[2].startswith('Hardware watchpoint')):   # wp hit
                if (self.is_valid_bt(self.gdb_execute('bt'))):
                    self.print_wp_hit(hit)
                    print ""
                    self.print_bt(self.gdb_execute('bt'))
                continue

            if (hit[2].startswith('Remote connection closed')):
                return

    def print_wp_hit(self, gdb_out):
        print ""
        print "\n".join(gdb_out[2:6])
        for lin in gdb_out[6:7]:
            print " ".join(lin.split(self.vmlinux_strip_prefix))

    def print_bt(self, gdb_out):
        for lin in gdb_out[1:]:
            split = lin.split(self.vmlinux_strip_prefix)
            print " ".join(split)

    def do_run(self, line):
        '''Run the vm and stop on wp hit.'''

        gdb_out = self.gdb_execute('c')

        if (len(gdb_out) == 3):
            #qemu process died due to entry into live mode
            #FIXME this is an assumption
            return

        #self.gdb_pexpect.interact()
        self.print_wp_hit(gdb_out)
        print ""
        self.print_bt(self.gdb_execute('bt'))

    def do_cont(self, line):
        self.gdb_pexpect.sendline('c')
        self.gdb_running = True

    def do_test_start_tracing(self, line):
        self.gdb_pexpect.sendcontrol('c')  # Ctrl-C
        self.gdb_pexpect.expect('\(gdb\)', 9999)
        logging.debug(self.gdb_pexpect.before)

        disp_out = self.gdb_execute('display/2i $pc')
        next_addr = disp_out[3].split(':')[0].strip()

        while True:
            # set bp, cont
            logging.debug("next_addr = {0}".format(next_addr))
            self.gdb_execute("del br 1")
            self.gdb_execute("b *{0}".format(next_addr))
            disp_out = self.gdb_execute('c')
            next_addr = disp_out[6].split(':')[0].strip()

    def do_test_gdb_exit(self, line):
        ins_count = 0
        print ""
        while True:
            if (ins_count % 1000 == 0):
                sys.stdout.write("Instructions processed = {0}\r".format(ins_count))
                sys.stdout.flush()
            ins_count += 1
            self.gdb_execute('c')

    def read_mem(addr, size):
        words = size / 4
        if (size % 4 != 0):
            words += 1
        data_raw = self.gdb_execute('x/{0} {1}'.format(words, addr))[1:]
        data = ""
        for line in data_raw:
            data += line.split(":")[1].replace("0x", "").replace("\t", "").replace(" ", "")

        if (size % 4 != 0):
            data = data[:-2 * (4 - (size % 4))]

        return data

    def do_start_tracing(self, line):
        if (self.gdb_running):
            self.gdb_pexpect.sendcontrol('c')
        # enable tracing mode
        self.gdb_execute('si')
        # set up display
        self.gdb_execute('display/i $pc')

        prev_mem_addr = None
        prev_mem_size = None
        prev_mem_data = None
        prev_eip = None
        prev_bt = None

        while True:
            # interpret instruction store mem_addr
            # for the last ins, check mem_addr
            cur = self.gdb_execute('c')
            # TODO verify that this is indeed an instruction trap due to our code
            # process last_ins's stuff
            if (prev_mem_addr is not None):
                new_data = self.read_mem(prev_mem_addr, prev_mem_size)
                if (prev_mem_data != new_data):
                    self.add_to_db(prev_eip, prev_mem_addr, prev_mem_data,
                            prev_mem_size, prev_mem_data, new_data, prev_bt)

            # prepare for cur_ins
            eip = cur[-1].split(":")[0][2:].strip()
            ins = cur[-1].split(":")[1].split()[0]
            args = cur[-1].split(":")[1].split()[1]
            logging.debug("eip={0}, ins={1}, args={2}".format(eip, ins, args))
            
            rel_addr, rel_size = self.decode_ins(ins, args)
            prev_mem_addr = rel_addr
            prev_mem_size = rel_size
            prev_mem_data = self.read_mem(rel_addr, rel_size)
            prev_eip = eip
            prev_bt = self.gdb_execute('bt') # FIXME format this
            

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true',
            help='Enable debug logging.')
    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    if (args.debug):
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.ERROR)

    dbg = RrDebugger()
    if os.path.exists('.rrdebuginit'):
        dbg.read_init_file('.rrdebuginit')
    dbg.cmdloop()
