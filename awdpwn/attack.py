# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #

"""
In short:
Traverse *.py in exps directory
run pwn_remote(ip, port, ..)
ips and ports are defined in targets.json.
"""
import sys
import importlib
import time
import os
import re

from threading import Thread
from timeout_decorator import timeout
from awdpwn.shell import is_shell_ok

from .utils import (
    p2mn, mn2n, n2mn, mn2p, get_exp_paths, get_shell_name,
    TargetsManager, confirm_exit
)
from .log import logger
from .config import config

if sys.version_info[0] < 3:
    from imp import reload
else:
    from importlib import reload


class Pwner(Thread):
    """Pwner that auto run exps"""

    def __init__(self, flag_queue, shells, scope, *args, **kwargs):
        super(Pwner, self).__init__(*args, **kwargs)
        self.scope = scope
        self.exps = {}
        self.flag_queue = flag_queue
        self.shells = shells
        self.load_exps()
        self.names = set(self.exps.keys()).intersection(
            set(TargetsManager.names()))

    def run(self):
        while True:
            threads = []
            pwn_interval = float(config.get('pwner', 'pwn_interval'))
            for name in self.names:
                # check enable
                if name not in TargetsManager.names() or not TargetsManager.get(name, 'enable'):
                    continue
                if not os.path.exists(mn2p(n2mn(name))):
                    continue
                # check scope
                if not self.inscope(name):
                    continue
                exp = self.exps[name]
                thread = Thread(target=Pwner.pwn_all,
                                args=(self, name, exp))
                thread.daemon = True
                threads.append(thread)
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            time.sleep(pwn_interval)

    def inscope(self, name):
        """whether name in scope"""
        if not self.scope:
            return True
        else:
            return name.startswith(self.scope + '.')

    def pwn_all(self, name, exp):
        ip_list, port, flag_pattern = TargetsManager.get(
            name, 'ips', 'port', 'flag_pattern')
        port = int(port)
        keep_shell = TargetsManager.get(name, 'keep_shell')
        for ip in ip_list:
            exp_timeout = float(config.get('pwner', 'exp_timeout'))
            try:
                abortable_pwn_remote = timeout(
                    exp_timeout, False)(exp.pwn_remote)
                flag, io = exp.pwn_remote(ip, port, keep_alive=keep_shell)
                self.flag_queue.put(flag)
                with_shell = 0
                # with_shell:
                # 0 : no shell
                # 1 : new shell
                # 2 : override shell
                # 3 : ignored new shell

                # maintain the shell connection
                if keep_shell:
                    shell_name = get_shell_name(name, ip, port)
                    old_shell = self.shells.get(shell_name, None)
                    if io and is_shell_ok(io):
                        with_shell = 3
                        if old_shell and not is_shell_ok(old_shell):
                            old_shell.close()
                            self.shells[shell_name] = io
                            with_shell = 2
                        elif not old_shell:
                            self.shells[shell_name] = io
                            with_shell = 1
                        else:
                            io.close()
                if with_shell == 1:
                    logger.info("[+] Pwn %s %s:%d ... [%s] with new shell", name, ip, port, flag)
                elif with_shell == 2:
                    logger.info("[+] Pwn %s %s:%d ... [%s] override shell", name, ip, port, flag)
                elif with_shell == 3:
                    logger.info("[+] Pwn %s %s:%d ... [%s] ignored shell", name, ip, port, flag)
                else:
                    logger.info("[+] Pwn %s %s:%d ... [%s]", name, ip, port, flag)
            except KeyboardInterrupt:
                confirm_exit()
            except Exception as ex:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                logger.info("[-] Pwn %s %s:%d ... %s(%s) at %s:%d",
                            name, ip, port, exc_type, ''.join(str(ex)), fname, exc_tb.tb_lineno)
                # ex.with_traceback()

    def load_exp(self, exp_path):
        '''load exp from exp_path. return False if fail to import'''
        module_name = p2mn(exp_path)
        name = mn2n(module_name)
        # check scope
        if not self.inscope(name):
            return
        if name in self.exps:
            module = self.exps[name]
            module = reload(module)
            self.exps[name] = module
            logger.info("[+] Reload exp of %s", name)
            return True
        try:
            module = importlib.import_module(module_name)
            if 'pwn_remote' not in dir(module):
                return False
            self.exps[name] = module
            logger.info("[+] Load exp of %s", name)
        except ImportError:
            return False

    def load_exps(self):
        exp_paths = get_exp_paths()
        self.exps = {}
        for exp_path in exp_paths:
            self.load_exp(exp_path)
