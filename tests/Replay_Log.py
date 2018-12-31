#!/usr/bin/python3
import csv
import math
from argparse import ArgumentParser as ArgParse
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from time import time, sleep

from constants import PORT_LEN
from tests.Test_Helpers import TIMESTAMP_INDEX, LENGTH_INDEX, get_all_address_ports, DEST_ADDR_INDEX, SRC_ADDR_INDEX, \
    PACKET_ID_INDEX
from util import i2b, ip2b

ETHERNET_STACK_OVERHEAD = 42  # Bytes


class Packet:
    ip = ip2b("127.0.0.1")

    def __init__(self, csv_row, port):
        self.packet_id = int(csv_row[PACKET_ID_INDEX])
        self.timestamp = float(csv_row[TIMESTAMP_INDEX])
        self.port = i2b(port, PORT_LEN)
        self.payload_len = int(csv_row[LENGTH_INDEX])

        self.payload_len -= ETHERNET_STACK_OVERHEAD

    def get_bytes(self):
        return Packet.ip + self.port + i2b(self.packet_id, 4) + bytes(self.payload_len)


def open_sockets(src_ports):
    src_sockets = dict()

    for addr, port in src_ports.items():
        sock = socket(AF_INET, UDP)
        sock.bind(("127.0.0.1", port))

        src_sockets[addr] = sock

    return src_sockets


if __name__ == "__main__":
    entry_addr = ("127.0.0.1", 20000)

    parser = ArgParse()
    parser.add_argument("packet_log")

    args = parser.parse_args()

    start_time = None

    src_ports, dest_ports = get_all_address_ports(args.packet_log)

    with open(args.packet_log, "r", newline="") as csv_file:
        packet_amount = len(csv_file.readlines())
        packets_sent = 0

        csv_file.seek(0)

        with open("tests/tmp/send-log", "w") as f:
            src_sockets = open_sockets(src_ports)

            packet_reader = csv.reader(csv_file, delimiter=",", quotechar="\"")

            for row in packet_reader:
                packet = Packet(row, dest_ports[row[DEST_ADDR_INDEX]])

                if start_time is not None:
                    current_time = time() - start_time

                    if current_time < packet.timestamp:
                        sleep(packet.timestamp - current_time)
                else:
                    start_time = time()

                f.write("{} {:.9f}\n".format(packet.packet_id, time()))
                src_sockets[row[SRC_ADDR_INDEX]].sendto(packet.get_bytes(), entry_addr)
                packets_sent += 1
                print("\r{}/{} {}%".format(packets_sent, packet_amount,
                                           math.floor(100 / packet_amount * packets_sent)),
                      end="")
