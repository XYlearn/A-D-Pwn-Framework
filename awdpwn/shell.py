# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #


""" Maintain the shell
"""

import socket
import sys
import re
import uuid
import threading

from threading import Thread
from cmd import Cmd

from .utils import get_shell_name, parse_shell_name, TargetsManager
from .config import config
from .log import logger

if sys.version_info[0] < 3:
    input = raw_input


PROMPT_TERM = '$$ '


class Shells(dict):
    def __init__(self, iterable={}):
        super(Shells, self).__init__(iterable)
        self.lock = {}

    def in_use(self, key):
        lock = self.lock.get(key)
        if not lock:
            return False
        return lock.locked()

    def release(self, key):
        lock = self.lock.get(key)
        if lock:
            lock.realease()

    def __getitem__(self, key):
        lock = self.lock.get(key)
        if lock:
            threading.Lock().acquire(True)
        val = super(Shells, self).__getitem__(key)
        return val

    def __setitem__(self, key, value):
        res = super(Shells, self).__setitem__(key, value)
        self.lock.__setitem__(key, threading.Lock())
        return res


class ShellManagerCli(Cmd):
    use_rawinput = False

    def __init__(self, flag_queue, shells, completekey='tab', stdin=None, stdout=None):
        super(ShellManagerCli, self).__init__(completekey, stdin, stdout)
        self.flag_queue = flag_queue
        self.shells = shells
        self.prompt = PROMPT_TERM

    def do_execute(self, arg):
        res = arg.split(None, 1)
        if len(res) != 2:
            self.write("Usage: execute TARGETS CMD\n")
            return
        target = res[0].strip()
        ios = self.get_ios(target)
        command = res[1].strip()
        if command.startswith('"'):
            command = eval(command)
        for shell_name, io in ios:
            self.write('[{}]\n'.format(shell_name))
            try:
                output = self.check_output(io, command)
            except IOError:
                self.write(
                    "[-] {} Broken ... Removed\n".format(shell_name))
                continue
            self.write(output)

    def do_get_flag(self, target):
        target = target.strip()
        if not target:
            ios = self.shells.items()
        else:
            ios = self.get_ios(target)
        for shell_name, io in ios:
            self.write('[{}]\n'.format(shell_name))
            name, _, _ = parse_shell_name(shell_name)
            cat_flag = TargetsManager.get(name, 'cat_flag')
            output = self.check_output(io, cat_flag)
            self.write(output + '\n')
            self.flag_queue.put(output.strip())

    def do_interact(self, target):
        target = target.strip()
        if not target:
            self.write("Usage: interact TARGET\n")
            return
        if target not in self.shells:
            self.write("{} not available\n".format(target))
            return
        io = self.shells[target]
        while True:
            self.write("[{}]".format(target) + PROMPT_TERM)
            command = self.readline()
            if command.strip() == 'detach':
                return
            try:
                output = self.check_output(io, command)
            except IOError:
                self.write("[-] Broken")
            if output:
                self.write(output)

    def do_ls(self, arg):
        msg = '\n'.join(self.shells.keys()) + '\n'
        self.write(msg)

    def read(self, size=-1):
        raw = self.stdin.read(size)
        return raw

    def readline(self, size=-1):
        raw = self.stdin.readline(size)
        return raw

    def write(self, data):
        self.stdout.write(data)
        self.stdout.flush()

    def get_args(self, arg):
        return arg.split()

    def get_ios(self, regex):
        targets = []
        regex = regex.strip()

        if regex == '*':
            for shell_name in self.shells:
                targets.append((shell_name, self.shells[shell_name]))
            return targets

        res = regex.split(":")
        if len(res) != 3:
            return None
        name, host, port = res
        pattern = name.replace('.', r'\.').replace('*', r'\w*') + r'\:' +\
            host.replace('.', r'\.').replace('*', r'\d*.\d*.\d*.\d*') + r'\:' +\
            port.replace('.', r'\.').replace('*', r'\d*')
        for shell_name in self.shells:
            if re.match(pattern, shell_name):
                targets.append((shell_name, self.shells[shell_name]))
        return targets

    def check_output(self, io, command):
        command = command.strip()
        if not command:
            return ''
        spliter = str(uuid.uuid1())
        command_warpper = '\necho {} ; {} ; echo {}\n'.format(
            spliter, command, spliter)
        io.send(command_warpper)
        io.recvuntil(spliter + '\n')
        output = io.recvuntil(spliter, drop=True)
        if isinstance(output, str):
            return output
        return output.decode('utf-8')


class ShellManagerServer(Thread):
    def __init__(self, flag_queue, shells, *args, **kwargs):
        super(ShellManagerServer, self).__init__(*args, **kwargs)
        self.flag_queue = flag_queue
        self.shells = shells
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        host = config['shell']['host']
        port = int(config['shell']['port'])
        try:
            self.sock.bind((host, port))
            self.sock.listen(5)
        except Exception as ex:
            logger.info(
                "[-] Fail to start ShellManagerServer ... Exception(%s)", ''.join(ex.args))
            return
        logger.info("[+] ShellManagerServer listen on %s:%d", host, port)

        while True:
            client, addr = self.sock.accept()
            worker = Thread(target=self.handle_client, args=(client, addr))
            worker.start()

    def handle_client(self, client, addr):
        logger.info(
            "[+] Client %s:%d connect to ShellManagerServer", addr[0], addr[1])
        try:
            pipe = client.makefile(mode='rw')
            ShellManagerCli(self.flag_queue, self.shells,
                            stdin=pipe, stdout=pipe).cmdloop()
        except OSError as e:
            pass
        except Exception as e:
            # pass
            e.with_traceback()
        logger.info(
            "[+] Client %s:%d disconnect from ShellManagerServer", addr[0], addr[1])


class ShellManagerClient:

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        host = config['shell']['server_host']
        port = int(config['shell']['server_port'])
        try:
            self.sock.connect((host, port))
        except IOError:
            print("[-] Fail to connect to {}:{}".format(host, port))
        while True:
            try:
                buf = ''
                while not buf.endswith(PROMPT_TERM):
                    try:
                        buf += self.sock.recv(1).decode('utf-8')
                    except IOError as e:
                        print(e)
                sys.stdout.write(buf)
                cmd = input() + '\n'
                striped_cmd = cmd.strip()
                if striped_cmd == 'quit' or striped_cmd == 'exit' or striped_cmd == 'q':
                    break
                self.sock.send(cmd.encode('utf-8'))
            except (IOError, KeyboardInterrupt, EOFError) as ex:
                print(ex)
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except IOError:
                    pass
                finally:
                    break
        print("Quit")


def is_shell_ok(io):
    try:
        test_str = str(uuid.uuid1())
        test_cmd = "\necho {};".format(test_str)
        io.sendline(test_cmd)
        if io.recvuntil(test_str, timeout=1.0):
            return True
    except EOFError:
        return False
    return False


if __name__ == "__main__":
    ShellManagerClient().start()
