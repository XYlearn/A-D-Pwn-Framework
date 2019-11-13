# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #


"""Utilizations for framework
"""

import os
import json
import re
import sys
import uuid
import json

from .config import awdpwn_path
from .log import logger

if sys.version_info[0] < 3:
    input = raw_input

targets_path = os.path.join(awdpwn_path, 'targets.json')


def p2mn(path):
    '''path to module name'''
    path = os.path.relpath(path, awdpwn_path)
    module_name = path[: -len('.py')]
    module_name = module_name.replace('/', '.')
    return module_name


def mn2n(module_name):
    '''module name to name'''
    name = module_name[len('exps.'): -len('.exp')]
    return name


def mn2p(module_name):
    '''module name to path'''
    path = module_name.replace('.', '/')
    path += '.py'
    return os.path.relpath(os.path.join(awdpwn_path, path), awdpwn_path)


def n2mn(name):
    '''name to module name'''
    module_name = 'exps.' + name + '.exp'
    return module_name


class TargetsManager(object):
    with open(os.path.join(awdpwn_path, "prelude/default_targets.json"), 'r') as f:
        default_targets_info = json.load(f)

    @classmethod
    def load(cls, silence=False):
        try:
            with open(targets_path, 'r') as f:
                cls.targets_info = json.load(f)
            if not silence:
                logger.info("[+] Load targets.json")
        except IOError:
            return False
        return True

    @classmethod
    def save(cls):
        try:
            with open(targets_path, 'w+') as f:
                json.dump(cls.targets_info, f, sort_keys=False,
                          indent=4, separators=(',', ': '))
        except IOError:
            return False
        return True

    @classmethod
    def remove(cls, name):
        if name in cls.targets_info:
            cls.targets_info.pop(name)
        else:
            keys_to_remove = []
            for key in cls.targets_info:
                if key.startswith(name + '.'):
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                cls.targets_info.pop(key)
        return cls.save()

    @classmethod
    def get(cls, name, *keys):
        if name not in cls.targets_info:
            parents = []
        else:
            parents = [name]
        parents += [s[:-1] for s in filter(name.startswith, [
            s + '.' for s in cls.targets_info.keys()])]
        parents.sort(reverse=True)
        parents.append('defaults')
        res = []
        for key in keys:
            found = False
            for parent in parents:
                parent_info = cls.targets_info[parent]
                if key in parent_info:
                    found = True
                    res.append(parent_info[key])
                    break
            if not found:
                res.append(None)
        if len(res) == 1:
            return res[0]
        else:
            return tuple(res)

    @classmethod
    def modify(cls, name, **kwargs):
        if name not in cls.targets_info:
            cls.targets_info[name] = {}
        for key, val in kwargs.items():
            cls.targets_info[name][key] = val
        return cls.save()

    @classmethod
    def create(cls, name, port=10001, enable=False):
        if name in cls.targets_info:
            return False
        cls.targets_info[name] = {
            'port': port,
            'enable': enable
        }
        return cls.save()

    @classmethod
    def names(cls):
        names = list(cls.targets_info.keys())
        names.remove('defaults')
        return names

    @classmethod
    def check(cls):
        if 'defaults' not in cls.targets_info:
            return False
        for key in cls.default_targets_info['defaults']:
            if key not in cls.targets_info:
                return False
        return True


# preload
TargetsManager.load(silence=True)


def confirm_exit(status=0):
    while True:
        try:
            ans = input("You really want to exit?(y/N)")
        except KeyboardInterrupt:
            continue
        break
    if ans.lower().startswith("y"):
        sys.exit(status)
    else:
        return


def get_exp_paths():
    exp_paths = []
    exps_root = os.path.join(awdpwn_path, 'exps')
    for root, _, files in os.walk(exps_root):
        for exp_file in filter(lambda path: path.endswith('.py'), files):
            exp_path = os.path.join(root, exp_file)
            exp_paths.append(exp_path)
    return exp_paths


def get_shell_name(name, ip, port):
    return "{}:{}:{}".format(name, ip, port)


def parse_shell_name(shell_name):
    matcher = re.match(r"^\w+(\.\w+)*\:\d+\.\d+\.\d+\.\d+\:\d+$", shell_name)
    if not matcher:
        return None
    return shell_name.split(':')


def alarm_incomplete(msg):
    logger.criticle(
        "[!] {} [Please check the framework completeness]".format(msg))
