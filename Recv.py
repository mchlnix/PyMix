#!/usr/bin/python3
# pylint: disable=C0111
from argparse import ArgumentParser as AP
from socket import socket, AF_INET, SOCK_DGRAM as UDP

parser = AP(description="Receives data on the specified ip:port using UDP " +
            "and prints it on stdout.")
parser.add_argument("ip:port", help="IP and Port pair to listen for" +
                    "datagrams on.")
parser.add_argument("-t", "--tcp", help="Use TCP instead of UDP to listen" +
                    "for data.", action="store_true")

BUFFER_SIZE = 65535

if __name__ == "__main__":
    args = parser.parse_args()

    print("Use Ctrl+C to quit.")

    ip, port = getattr(args, "ip:port").split(":")
    port = int(port)
    print("Listening on {}:{}".format(ip, port))

    sock = socket(AF_INET, UDP)
    sock.bind((ip, port))

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)

            print(addr, len(data), data.decode("utf-8"))
            sock.sendto(bytes("Got Message. Thanks.", "utf-8"), addr)

        except KeyboardInterrupt as kbi:
            print("Received Ctrl+C, quitting.")
            break
