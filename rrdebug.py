#!/usr/bin/python

from cmd import Cmd
import subprocess
import pexpect
import os
import logging
import time
import argparse
import sys
import sqlite3
import datetime
import re


class RrDebugger(Cmd):
    def init_db(self):
        self.conn = sqlite3.connect(self.db_file_name)
        self.cursor = self.conn.cursor()

    def setup_db(self):
        if (os.path.exists(self.db_file_name)):
            logging.ERROR('DB already exists! Quitting.')
            sys.exit(-1)
        # Run queries to create table and index
        self.cursor.execute('CREATE TABLE logs\
                (eip CHAR(8),\
                timestamp timestamp,\
                mem_addr text,\
                old_data text,\
                new_data text,\
                bt text\
                )')
        self.cursor.execute('CREATE INDEX eip_index ON logs(eip)')
        self.conn.commit()

    def __init__(self):
        Cmd.__init__(self)
        # Constants
        self.prompt = 'rr_dbg>'
        self.qemu_replay_keyword = '-replay'
        self.gdb_connect_cmd = 'target remote localhost:1234'
        self.setup_time = 8

        # Regexes
        # '=> 0xc000c000:\tmov\t%eax,0x20(%ebx)\n'
        self.ins_line_regex = re.compile('.*0x(.*):\s*([a-z]+)\s*(.*)\s*')

        # read from init file
        self.vmlinux = 'vmlinux'
        self.vmlinux_strip_prefix = ''
        self.gdb_exec = '/usr/bin/gdb'
        self.qemu_exec = 'qemu'
        self.qemu_args = ['-s', '-no-reboot']
        self.qemu_replay_file = 'r.log'
        self.gdb_macros = None
        self.executable = None
        self.qemu_cwd = None
        self.image = None

        # Processes, dynamic data, flags
        self.qemu_process = None
        self.gdb_pexpect = None
        self.executable_start_dump = None
        self.gdb_running = False

        # DB stuff
        self.db_file_name = 'rrdebug.sqlite'
        self.conn = None
        self.cursor = None

    def add_to_db(self, eip, mem_addr, old_data, mem_size, new_data, bt):
        logging.info("Adding to db: {0}".format(locals()))
        tup = (eip, datetime.datetime.now(), mem_addr, old_data, new_data, bt)
        try:
            self.cursor.execute('INSERT into logs VALUES (?,?,?,?,?,?)', tup)
        except sqlite3.IntegrityError, e:
            logging.error("Database raised exception: {0}".format(str(e)))

        self.conn.commit()

    def read_init_file(self, filename):
        f = open(filename, 'r')
        for line in f:
            self.onecmd(line)

        logging.debug('Init file loaded.')

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
        logging.debug("gdb_execute: " + cmd + " : " + self.gdb_pexpect.before)
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

    def interrupt(self):
        self.gdb_pexpect.sendcontrol('c')  # Ctrl-C
        self.gdb_pexpect.expect('\(gdb\)', 9999)

    def do_test_start_tracing(self, line):
        self.interrupt()

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
                sys.stdout.write("Instructions processed = {0}\r".
                        format(ins_count))
                sys.stdout.flush()
            ins_count += 1
            self.gdb_execute('c')

    def read_mem(self, addr, size):
        words = size / 4
        if (size % 4 != 0):
            words += 1
        data_raw = self.gdb_execute('x/{0} 0x{1}'.format(words, addr))[1:]
        logging.debug("read_mem: raw: {0}".format(data_raw))
        data = ""
        for line in data_raw:
            data += line.split(":")[1].replace("0x", "").replace("\t", "").\
            replace(" ", "")

        if (size % 4 != 0):
            data = data[:-2 * (4 - (size % 4))]

        return data

    def hex_add(self, sign, a, b):
        if (a == ''):
            a = '0'
        if (sign == '-'):
            return hex((int(a, 16) * -1) + int(b, 16))[2:]
        else:
            return hex(int(a, 16) + int(b, 16))[2:]

    def read_reg(self, reg):
        #l = self.gdb_execute('p/x ${0}'.format(reg))
        #logging.debug("read_reg line: {0}".format(l))
        return self.gdb_execute('p/x ${0}'.format(reg))[1].\
                split("=")[1].strip()[2:]

    def decode_ins(self, ins, args):
        ''' Return the mem_addr/size that this instruction will modify.
        Return None, None otherwise. '''
        # NOTE We ignore all stack operations
        # NOTE All operations are assumed to act on 4 bytes
        # NOTE Ignoring all rep instructions
        ignored_ins = set(['cmp', 'ja', 'test', 'call', 'ret', 'pop',
            'push', 'jne', 'jnz', 'rep', 'jmp', 'ja', 'je', 'jb'])
        if ins in ignored_ins:
            return None, None

        if (len(args.split(",")) != 2):
            logging.info("Args length != 2. Skipping.. {0}: {1}"\
                    .format(ins, args))
            return None, None
        #import pdb; pdb.set_trace()
        src, dest = args.split(",")
        logging.debug("Decoding {0}: {1}, {2}".format(ins, src, dest))

        # dest can be reg, immediate or 0x20(%eax) or (blah, blah, blah)
        # TODO handle case4
        case1_regex = re.compile("%[a-z]*")
        case2_regex = re.compile("$0x(.*)")
        case3_regex = re.compile("(-?)0?x?(.*)\(%([a-z]*)\)")

        mo = case1_regex.match(dest)
        if (mo is not None):
            return None, None

        mo = case2_regex.match(dest)
        if (mo is not None):
            imm_addr = mo.groups()[0]
            return imm_addr, 4

        mo = case3_regex.match(dest)
        if (mo is not None):
            sign, offset, reg = mo.groups()
            return self.hex_add(sign, offset, self.read_reg(reg)), 4

        logging.info("Dest format not handled!: {0}: {1}".format(ins, args))
        return None, None

    def do_interact(self, line):
        self.interrupt()
        self.gdb_pexpect.interact()

    def do_start_tracing(self, line):
        if (self.gdb_running):
            self.interrupt()
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
            # TODO verify that this is indeed an instruction trap due
            # to our code
            # process last_ins's stuff
            if (prev_mem_addr is not None):
                new_data = self.read_mem(prev_mem_addr, prev_mem_size)
                if (prev_mem_data != new_data):
                    self.add_to_db(prev_eip, prev_mem_addr, prev_mem_data,
                            prev_mem_size, new_data, prev_bt)

            # prepare for cur_ins
            #logging.debug("Ins line: {0}".format(cur[-1]))
            if (cur[-1].startswith('Cannot access')):
                continue
            eip, ins, args = self.ins_line_regex.match(cur[-1]).groups()
            logging.debug("eip={0}, ins={1}, args={2}".format(eip, ins, args))

            rel_addr, rel_size = self.decode_ins(ins, args)
            prev_mem_addr = rel_addr
            prev_mem_size = rel_size
            if (rel_addr is not None):
                prev_mem_data = self.read_mem(rel_addr, rel_size)
                prev_eip = eip
                # FIXME format bt
                prev_bt = '\n'.join(self.gdb_execute('bt')[2:])


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true',
            help='Enable debug logging.')
    parser.add_argument('-c', '--createdb', action='store_true',
            help='Create a new database.')
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
    if (args.createdb):
        dbg.init_db()
        dbg.setup_db()
    else:
        if os.path.exists(dbg.db_file_name):
            dbg.init_db()
        else:
            logging.error("DB file not found.")
            sys.exit(-1)

    dbg.cmdloop()
