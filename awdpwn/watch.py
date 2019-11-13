# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #


"""Use watchdog to monitor modifications and reload while neccessary
"""

import os
import json

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler, FileCreatedEvent,
    FileModifiedEvent, FileDeletedEvent
)
from .utils import p2mn, mn2n, TargetsManager

from .config import load_config


class WatchHandler(FileSystemEventHandler):
    def __init__(self, pwner, *args, **kwargs):
        super(WatchHandler, self).__init__(*args, **kwargs)
        self.pwner = pwner

    def on_created(self, event):
        if not isinstance(event, FileCreatedEvent):
            return
        path = event.src_path
        if not path.endswith('exp.py'):
            return
        self.pwner.load_exp(path)

    def on_modified(self, event):
        if not isinstance(event, FileModifiedEvent):
            return
        path = os.path.relpath(event.src_path)
        if path == 'config.ini':
            load_config()
        elif path == 'targets.json':

            TargetsManager.load()
        elif not path.endswith('exp.py'):
            return
        else:
            self.pwner.load_exp(path)

    def on_deleted(self, event):
        if not isinstance(event, FileDeletedEvent):
            return
        path = event.src_path
        if not path.endswith('exp.py'):
            return
        name = mn2n(p2mn(path))
        TargetsManager.remove(name)
        exps = self.pwner.exps
        if name in exps:
            exps.pop(name)
