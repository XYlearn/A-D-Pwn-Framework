# -*- codeing: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #

import logging
import sys
import os

from .config import awdpwn_path

def get_logger():
    logger = logging.getLogger("global")
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(os.path.join(awdpwn_path, 'awd.log'))

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    output_handler = logging.StreamHandler(sys.stderr)
    logger.addHandler(output_handler)
    return logger

logger = get_logger()