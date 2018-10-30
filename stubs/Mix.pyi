from socket import socket

from Types import AddressTuple
from Ciphers.Cipher import Cipher

STORE_LIMIT: int

EXPLICIT_IV_SIZE: int

class Mix:
    cipher: Cipher
    incoming: socket
    next_addr: AddressTuple
    mix_addr: AddressTuple

    def get_outgoing_chan_id(self, in_chan_id: int) -> int: ...
    def handle_mix_fragment(self, payload: bytes) -> None: ...
    def handle_response(self, payload: bytes) -> None: ...
    def run(self) -> None: ...
