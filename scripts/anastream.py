#!python3
# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------- #
# "THE TEA-WARE LICENSE" (ver 1):                                                      #
# <xylearn@qq.com> wrote this file. As long as you retain this notice you can  #
# do whatever you want with this stuff. If you meet me some day, and you think #
# this stuff is worth it, you can buy me a cup of tea in return. XYlearn       #
# ---------------------------------------------------------------------------- #

"""
This script can extract exp from pcap
commands:
    list
        :This will show all available stream. Each stream only has one direction
    extract stream_id [dest_path]
        :extract stream to exp
    hexdump stream_id
        :print hexdump of stream
"""

import sys
import argparse
import cmd
import functools

from scapy.all import *

# TODO implement PacketManager with Tshark
# Tshark PacketManager
# tshark -r {path} -q -z follow,tcp,raw,{idx}
# tshark -r {path} -T fields -e tcp.stream | sort | uniq -c | wc -l

class ExpGenerator(object):
    def gen_exp(self, payloads):
        lines = []
        for payload in payloads:
            lines.extend(self.gen_one(payload))
        before = [
            "from pwn import *",
            "import time",
            "",
            "def get_io(debug=True):",
            "\tio = proess("", env={'LD_PRELOAD': ''})"
            "\tcontext.clear(log_level='DEBUG')"
            "\treturn io",
            "",
            "def get_flag(io):",
        ]
        after = [
            "",
            "if __name__ == '__main__':",
            "\tio = get_io()",
            "\tflag = get_flag(io)",
            "\tio.interactive()",
            "\tprint(flag)"
        ]
        return '\n'.join(before + list(map(lambda s: '\t' + s, lines)) + after)

    def gen_one(self, payload, delay=0.5):
        lines = []
        lines.append("time.sleep({})".format(delay))
        lines.append("io.send({})".format(repr(payload)))
        return lines


class PacketManager(object):
    def __init__(self, pcap):
        self.pcap = pcap
        self.streams = list(self.pcap.sessions().items())

    def list_streams(self):
        for idx, (key, val) in enumerate(self.streams):
            print("{}. {} {}".format(idx, key, val))

    def get_stream(self, stream_idx):
        if stream_idx < 0 or stream_idx >= len(self.streams):
            return None
        return self.streams[stream_idx][1]

    def filter_packets(self, packets):
        packets = packets.filter(
            lambda packet: len(packet) and (TCP in packet))
        return packets

    def get_payloads(self, packets):
        packets = self.filter_packets(packets)
        payloads = map(lambda packet: bytes(packet['TCP'].payload), packets)
        payloads = list(filter(len, payloads))
        return payloads

    def hexdump_stream(self, stream_idx):
        if stream_idx < 0 or stream_idx >= len(self.streams):
            return False
        packets = self.streams[stream_idx][1]
        packets = self.filter_packets(packets)
        for packet in packets:
            packet = packet['TCP']
            payload = packet.payload
            if not len(payload):
                continue
            print(packet.summary())
            hexdump(payload)
        return True


class UserShell(cmd.Cmd):
    def __init__(self, pcap, completekey='tab', stdin=None, stdout=None):
        super(UserShell, self).__init__(completekey, stdin, stdout)
        self.pcap = pcap
        self.sessions = list(self.pcap.sessions().items())
        self.eg = ExpGenerator()
        self.pm = PacketManager(pcap)

    def parse_args(self, arg):
        return list(filter(len, arg.split()))

    def do_list(self, arg):
        self.pm.list_streams()

    def do_extract(self, arg):
        args = self.parse_args(arg)
        if len(args) != 1 and len(args) != 2:
            print("Usage: extract index [path]")
            return
        index = int(args[0])
        packets = self.pm.get_stream(index)
        if packets is None:
            print("Index out of range.")
        payloads = self.pm.get_payloads(packets)
        if len(args) == 2:
            path = args[1]
        else:
            path = 'exp0.py'
        args = self.parse_args(arg)
        exp = self.eg.gen_exp(payloads)
        try:
            with open(path, "w+") as f:
                f.write(exp)
        except IOError:
            print("Fail to write {}".format(repr(path)))

    def do_hexdump(self, arg):
        args = self.parse_args(arg)
        if len(args) != 1:
            print("Usage: hexdump index")
        index = int(args[0])
        if not self.pm.hexdump_stream(index):
            print("Index out of range.")

    def do_exit(self, arg):
        sys.exit(0)

    def do_quit(self, arg):
        self.do_exit(arg)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    pcap_path = args.pcap
    try:
        pcap = rdpcap(pcap_path)
    except IOError:
        print("Fail to open {}".format(repr(pcap_path)))
        sys.exit(0)
    extractor = UserShell(pcap)
    extractor.cmdloop()


if __name__ == '__main__':
    main()
