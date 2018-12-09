from socket import socket

from Types import AddressTuple

from LinkEncryption import LinkDecryptor, LinkEncryptor


class ExitPoint:
    mix_addr: AddressTuple
    sock_to_mix: socket

    link_decryptor: LinkDecryptor
    link_encryptor: LinkEncryptor

    def __init__(self, own_addr: AddressTuple) -> None: ...
    def run(self) ->  None: ...
