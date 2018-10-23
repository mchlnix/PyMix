#!/usr/bin/python3
from argparse import ArgumentParser as ArgParse
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from time import time, sleep

from util import i2b, ip2b

ip, port = "127.0.0.1", 60001
entry_addr = ("127.0.0.1", 20000)

to_send = 1 * 1000*1000  # bytes

sock = socket(AF_INET, UDP)

parser = ArgParse()
parser.add_argument("packet_log")

args = parser.parse_args()

start_time = None

with open(args.packet_log, "r") as f:
    for line in f.readlines():
        pack_id, timestamp, _, _, prot, *_ = line.split(" ")

        pack_id = int(pack_id)
        timestamp = float(timestamp)

        if prot == "UDP":
            pack_len = int(line.split(" ")[8].split("=")[1])

        else:
            pack_len = 102  # magic number taken from log

        if start_time is None:
            start_time = time()
        else:
            current_time = time() - start_time

            if current_time < timestamp:
                sleep(timestamp - current_time)

        print(pack_id, "{:.9f}".format(time()))
        sock.sendto(ip2b(ip) + i2b(port, 2) + i2b(pack_id, 4) + bytes(pack_len), entry_addr)
