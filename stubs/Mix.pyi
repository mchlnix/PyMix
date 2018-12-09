from socket import socket
from typing import Any

from Types import AddressTuple
from petlib.bn import Bn

from LinkEncryption import LinkEncryptor, LinkDecryptor

STORE_LIMIT: int

class Mix:
    priv_comp: Bn
    pub_comp: Any
    incoming: socket
    next_addr: AddressTuple
    mix_addr: AddressTuple

    request_link_encryptor: LinkEncryptor
    response_link_encryptor: LinkEncryptor
    request_link_decryptor: LinkDecryptor
    response_link_decryptor: LinkDecryptor

    def get_outgoing_chan_id(self, in_chan_id: int) -> int: ...
    def handle_mix_fragment(self, payload: bytes) -> None: ...
    def handle_response(self, payload: bytes) -> None: ...
    def run(self) -> None: ...
