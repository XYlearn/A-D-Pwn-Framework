#!python
# -*- codeing: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #


import json
import os
import sys
import click
import shutil

from watchdog.observers import Observer
if sys.version_info[0] < 3:
    from Queue import Queue
else:
    from queue import Queue

from awdpwn.utils import (
    n2mn, mn2p, TargetsManager, confirm_exit, alarm_incomplete
)
from awdpwn.attack import Pwner
from awdpwn.watch import WatchHandler
from awdpwn.submit import Submitter
from awdpwn.shell import Shells, ShellManagerServer, ShellManagerClient
from awdpwn.config import awdpwn_path

try:
    with open(os.path.join(awdpwn_path, "prelude/exp_template.py"), 'r') as f:
        exp_template = f.read()
except IOError:
    alarm_incomplete("prelude/exp_template.py is missing")
    sys.exit(0)


if sys.version_info[0] < 3:
    input = raw_input


@click.group()
def cli():
    pass


@cli.command()
@click.argument('name')
@click.option('--binary', default='pwn', help="path/to/binary")
@click.option('--port', default=10001, help="port of gamebox")
def add(name, binary, port):
    """Add a expolits namespace
    """
    path = mn2p(n2mn(name))
    if os.path.exists(path):
        click.echo("{} Existed".format(name), err=True)
        return
    dirname = os.path.dirname(path)
    try:
        os.makedirs(dirname)
    except IOError:
        pass
    tmp = dirname
    while tmp:
        try:
            open(os.path.join(tmp, '__init__.py'), 'a').close()
        except IOError:
            pass
        tmp = os.path.dirname(tmp)
    exp = exp_template.format(binary=binary)
    try:
        with open(path, 'w+') as f:
            f.write(exp)
    except IOError:
        click.echo("Fail to create and write {}".format(path), err=True)
        return
    TargetsManager.create(name, port)


@cli.command()
@click.argument('name')
def remove(name):
    """Remove a exploits namespace
    """
    path = mn2p(n2mn(name))
    dirname = os.path.dirname(path)
    # filename = os.path.basename(path)
    try:
        shutil.rmtree(dirname)
    except OSError:
        pass
    # remove from targets.json
    TargetsManager.remove(name)


@cli.command()
@click.argument('name')
def disable(name):
    """Disable namespace
    """
    TargetsManager.modify(name, enable=False)


@cli.command()
@click.argument('name')
def enable(name):
    """Enable namespace
    """
    TargetsManager.modify(name, enable=True)


@cli.command()
@click.option('--enabled-only', '-e', is_flag=True, default=False)
def ls(enabled_only):
    """List namespace configured in targets.json
    """
    for name in TargetsManager.names():
        enabled = TargetsManager.get(name, 'enable')
        if enabled_only and not enabled:
            continue
        path = mn2p(n2mn(name))
        if not os.path.exists(path):
            continue
        line = '{} [enabled:{}]'.format(name, enabled)
        click.echo(line)


@cli.command()
@click.argument('scope', default='')
def run(scope):
    """Run the awdpwn framework
    """
    flag_queue = Queue()
    shells = Shells()
    pwner = Pwner(flag_queue, shells, scope)
    pwner.daemon = True
    submitter = Submitter(flag_queue)
    submitter.daemon = True
    observer = Observer()
    observer.daemon = True
    smserver = ShellManagerServer(flag_queue, shells)
    smserver.daemon = True
    handler = WatchHandler(pwner)
    observer.schedule(handler, ".", recursive=True)

    observer.start()
    pwner.start()
    smserver.start()
    submitter.start()

    while True:
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            confirm_exit()


@cli.command()
def sm():
    """Attach to shell manager
    """
    smc = ShellManagerClient()
    smc.daemon = True
    smc.start()


@cli.command()
@click.argument('flag')
def submit(flag):
    """Submit a flag
    """
    flag_queue = Queue()
    submitter = Submitter(flag_queue)
    submitter.submit(flag)


if __name__ == "__main__":
    cli()
