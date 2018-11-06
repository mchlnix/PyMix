from socket import socket

from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Types import AddressTuple

STORE_LIMIT: int

class Mix:
    cipher: PKCS1OAEP_Cipher
    incoming: socket
    next_addr: AddressTuple
    mix_addr: AddressTuple

    def get_outgoing_chan_id(self, in_chan_id: int) -> int: ...
    def handle_mix_fragment(self, payload: bytes) -> None: ...
    def handle_response(self, payload: bytes) -> None: ...
    def run(self) -> None: ...
