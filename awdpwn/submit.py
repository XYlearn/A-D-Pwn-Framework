# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #


import sys
import os
import time
import json

from threading import Thread
if sys.version_info[0] < 3:
    from Queue import Queue
else:
    from queue import Queue


import requests

from .log import logger
from .config import config
from .utils import confirm_exit, awdpwn_path


class Submitter(Thread):
    def __init__(self, queue, *args, **kwargs):
        super(Submitter, self).__init__(*args, **kwargs)
        self.setDaemon(True)
        self.token = config.get("submit", "token")
        self.url = config.get("submit", "url")
        self.fail_text = config.get("submit", "fail_text")
        self.queue = queue

    def do_submit(self, flag):
        with open(os.path.join(awdpwn_path, 'submit.json'), 'r') as f:
            meta_str = f.read()
            meta_str.format(flag=flag)
            meta = json.loads(meta_str)
        try:
            response = requests.post(self.url, timeout=2.0, **meta)
        except Exception:
            msg = "[-] Submit flag : [{}] ... !!Failed!! ({})".format(
                flag, "Can't post to {}".format(self.url))
            logger.info(msg)
            return False
        content = response.content
        if self.fail_text in content:
            msg = "[-] Submit flag : [{}] ... !!Failed!! ({})".format(
                flag, content)
            logger.info(msg)
            return False
        else:
            msg = "[+] Submit flag : [{}] ... !!Success!! ({})".format(
                flag, content)
            logger.info(msg)
            return True

    def submit(self, flag):
        try:
            self.do_submit(flag)
        except KeyboardInterrupt as ex:
            confirm_exit()
            self.queue.put(flag)
        except Exception as ex:
            msg = "[-] Submit flag : [{}] ... !!Failed!! ({})".format(
                flag, ' '.join(ex.args))
            logger.info(msg)
            return False

    def run(self):
        while True:
            flag = self.queue.get()
            self.do_submit(flag)


def main():
    flag_queue = Queue()
    submitter = Submitter(flag_queue)
    if len(sys.argv) != 2:
        print("Usage: submit.py [flag]")
        exit()
    flag = sys.argv[1]
    submitter.start()
    flag_queue.put(flag)
    time.sleep(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
