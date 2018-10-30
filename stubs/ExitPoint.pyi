from socket import socket

from Types import AddressTuple


class ExitPoint:
    mix_addr: AddressTuple
    sock_to_mix: socket

    def run(self) ->  None: ...
