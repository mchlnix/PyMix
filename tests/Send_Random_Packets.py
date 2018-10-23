#!/usr/bin/python3

from random import randrange
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from time import time, sleep

from util import i2b, ip2b

MIN_MSG_SIZE = 10
MAX_MSG_SIZE = 1000 - 6  # ip and port

ip, port = "127.0.0.1", 60001
entry_addr = ("127.0.0.1", 20000)

to_send = 1 * 1000*1000  # bytes

sock = socket(AF_INET, UDP)

start = time()

packets = 1

while to_send > 0:
    msg_size = randrange(MIN_MSG_SIZE, MAX_MSG_SIZE)
    pack_id = i2b(packets, 4)

    try:
        sock.sendto(ip2b(ip) + i2b(port, 2) + pack_id + bytes(msg_size - 4), entry_addr)
        print(packets, msg_size)
    except OSError:
        continue

    packets += 1
    to_send -= msg_size

    sleep(0.01)


print("Sent", packets, "packets in", time() - start, "seconds.")
