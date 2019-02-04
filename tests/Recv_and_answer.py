#!/usr/bin/python3
from argparse import ArgumentParser as ArgParse
from socket import socket, AF_INET, SOCK_DGRAM as UDP

parser = ArgParse(description="Receives data on the specified ip:port using UDP and prints it on stdout.")
parser.add_argument("ip:port", help="IP and Port pair to listen for datagrams on.")

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

            try:
                payload = data.decode("utf-8")
                print(addr, len(data), data.decode("utf-8"))
            except UnicodeDecodeError as ude:
                print("Couldn't display payload.")

                sock.sendto(data, addr)

        except KeyboardInterrupt:
            print("Received Ctrl+C, quitting.")
            break
