#!/usr/bin/python3 -u
from argparse import ArgumentParser as ArgParse
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from time import time

from util import b2i

parser = ArgParse(description="Receives data on the specified ip:port using UDP and prints it on stdout.")
parser.add_argument("ip:port", help="IP and Port pair to listen for datagrams on.")

BUFFER_SIZE = 65535

if __name__ == "__main__":
    args = parser.parse_args()

    ip, port = getattr(args, "ip:port").split(":")
    port = int(port)

    sock = socket(AF_INET, UDP)
    sock.bind((ip, port))

    packets = 0

    start_time = None

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)

            if start_time is None:
                start_time = time()

            packets += 1

            print(str(b2i(data[0:4])).rjust(7), "{:.9f}".format(time()))

        except KeyboardInterrupt:
            break
