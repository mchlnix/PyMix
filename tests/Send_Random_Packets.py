#!/usr/bin/python3
from random import randrange, random
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from time import time, sleep
from sys import argv

from util import i2b, ip2b

sleep(random())

MIN_MSG_SIZE = 10
MAX_MSG_SIZE = 1000 - 6  # ip and port

ip, port = "127.0.0.1", 45000
entry_addr = ("127.0.0.1", 20000)

if len(argv) > 1:
    to_send = int(argv[1])
else:
    to_send = -1

sock = socket(AF_INET, UDP)

start = time()

packets = 1

while to_send != 0:
    msg_size = randrange(MIN_MSG_SIZE, MAX_MSG_SIZE)
    pack_id = i2b(packets, 4)

    try:
        sock.sendto(ip2b(ip) + i2b(port, 2) + pack_id + bytes(msg_size - 4),
                    entry_addr)
    except OSError:
        continue

    to_send -= 1

    sleep(1/20)

print("Sent", packets, "packets in", time() - start, "seconds.")
