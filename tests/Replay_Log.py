#!/usr/bin/python3
import csv
from argparse import ArgumentParser as ArgParse
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from time import time, sleep

from util import i2b, ip2b

PACKET_ID_INDEX = 0
TIMESTAMP_INDEX = 1
PROTOCOL_INDEX = 4
LENGTH_INDEX = 5

ETHERNET_STACK_OVERHEAD = 42  # Bytes


class Packet:
    ip, port = ip2b("127.0.0.1"), i2b(60001, 2)

    def __init__(self, csv_row):
        self.packet_id = int(csv_row[PACKET_ID_INDEX])
        self.timestamp = float(csv_row[TIMESTAMP_INDEX])
        self.payload_len = int(csv_row[LENGTH_INDEX])

        self.payload_len -= ETHERNET_STACK_OVERHEAD

    def get_bytes(self):
        return Packet.ip + Packet.port + i2b(self.packet_id, 4) + bytes(self.payload_len)


entry_addr = ("127.0.0.1", 20000)

sock = socket(AF_INET, UDP)

parser = ArgParse()
parser.add_argument("packet_log")

args = parser.parse_args()

start_time = None

with open(args.packet_log, "r", newline="") as csv_file:
    packet_reader = csv.reader(csv_file, delimiter=",", quotechar="\"")
    for row in packet_reader:
        packet = Packet(row)

        if start_time is not None:
            current_time = time() - start_time

            if current_time < packet.timestamp:
                sleep(packet.timestamp - current_time)
        else:
            start_time = time()

        print(packet.packet_id, "{:.9f}".format(time()))
        sock.sendto(packet.get_bytes(), entry_addr)
