# -*- codeing: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #

import sys
import os

if sys.version_info[0] < 3:
    from ConfigParser import ConfigParser
else:
    from configparser import ConfigParser

awdpwn_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config():
    global config
    config = ConfigParser()
    config.read(os.path.join(awdpwn_path, "config.ini"))
    return config


config = load_config()
