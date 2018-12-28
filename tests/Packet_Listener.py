#!/usr/bin/python3 -u
from selectors import DefaultSelector, EVENT_READ
from signal import signal, SIGTERM
from socket import socket, AF_INET, SOCK_DGRAM
from sys import argv
from time import time

from constants import UDP_MTU
from util import b2i

socket_selector = DefaultSelector()

output_file = argv[1]

for port_number in argv[2:]:
    listener_socket = socket(AF_INET, SOCK_DGRAM)
    listener_socket.bind(("127.0.0.1", int(port_number)))

    socket_selector.register(listener_socket, EVENT_READ)


def set_killed(_signal, _stackframe):
    global killed

    killed = True


signal(SIGTERM, set_killed)

killed = False

with open(output_file, "w") as f:
    while not killed:
        events = socket_selector.select(timeout=2)

        for key, _ in events:
            sock = key.fileobj

            if isinstance(sock, socket):
                data = sock.recv(UDP_MTU)

                f.write("{} {:.9f}\n".format(str(b2i(data[0:4])).rjust(7), time()))
                f.flush()
