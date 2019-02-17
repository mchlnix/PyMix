#!/usr/bin/python3

import select
from socket import socket, AF_INET, SOCK_STREAM

from constants import IPV4_LEN, PORT_LEN
from util import b2i, b2ip, i2b

IP = "127.0.0.1"
PORT = 20004
OPEN_CONNECTIONS = 10

to_mix = socket(AF_INET, SOCK_STREAM)
to_mix.bind((IP, PORT))
to_mix.listen(OPEN_CONNECTIONS)

print(f"Listening on {IP}:{PORT}")

read_list = [to_mix]
initialized_dict = {}


if __name__ == "__main__":
    while True:
        readable, _, _ = select.select(read_list, [], [])

        for s in readable:
            if s is to_mix:
                client_socket, address = to_mix.accept()
                read_list.append(client_socket)
                print(f"Connection from {address}")
            else:
                if s in initialized_dict:
                    length = s.recv(2)

                    if length:
                        len_int = b2i(length)

                        data = s.recv(len_int)

                        utf = "utf-8"
                        print(f"Got data message from {s.getpeername()}. Length: {len_int}")
                        print(data)
                        s.send(i2b(len(data), 2) + data)
                    else:
                        s.close()
                        read_list.remove(s)
                        try:
                            del initialized_dict[s]
                        except ValueError:
                            pass

                        continue
                else:
                    version = s.recv(1)
                    command = s.recv(1)
                    addr_type = s.recv(1)
                    ip = s.recv(IPV4_LEN)
                    dest_port = s.recv(PORT_LEN)
                    src_port = s.recv(PORT_LEN)

                    assert version == b'\x01', version
                    assert command == b'\x04', command
                    assert addr_type == b'\x01', addr_type

                    ip = b2ip(ip)
                    port = b2i(dest_port)

                    print(f"Got init message from {s.getpeername()} for {ip}: {port}")

                    initialized_dict[s] = (ip, port)
