from socket import socket

from Types import AddressTuple
from Ciphers.Cipher import Cipher

STORE_LIMIT: int
CHAN_ID_SIZE: int
MIN_CHAN_ID: int
MAX_CHAN_ID: int
EXPLICIT_IV_SIZE: int

class Mix:
    cipher: Cipher
    incoming: socket
    next_addr: AddressTuple
    mix_addr: AddressTuple

    def get_outgoing_chan_id(self, in_chan_id: int) -> int: ...
    def handle_mix_fragment(self, payload: bytes) -> int: ...
    def handle_response(self, payload: bytes) -> None: ...
    def run(self) -> None: ...

def random_channel_id() -> int: ...
def get_chan_id(payload: bytes) -> int: ...
def get_payload(packet: bytes) -> bytes: ...
