#!/usr/bin/python3
from random import randint, choice
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from util import i2b, ip2b

num_of_requests = 10

requests = ["Hello"]*num_of_requests

dest_ports = [60001, 60002, 60003, 60004, 60005]

entry_addr = ("127.0.0.1", 20000)


def header(ip, port):
    return ip2b(ip) + i2b(port, 2)


if __name__ == "__main__":
    # get a receiver with a random port in the 5xxxx
    ip = "127.0.0.1"
    port = randint(50000, 59999)

    sock = socket(AF_INET, UDP)
    sock.bind(("127.0.0.1", port))

    print("Sending from", ip, port)

    # send requests to predetermined destinations
    for payload in requests:
        dest_port = choice(dest_ports)

        print("Sending", payload.encode("utf-8"), "to", dest_port, "len:", len(payload.encode("utf-8")))
        sock.sendto(header(ip, dest_port) + payload.encode("utf-8"),
                    entry_addr)

    # wait for responses and check with what we expected
    while True:
        data, addr = sock.recvfrom(4096)

        print(addr, len(data), data)
