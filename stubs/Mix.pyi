from socket import socket

from Types import AddressTuple
from petlib.bn import Bn
from petlib.ec import EcPt

from LinkEncryption import LinkEncryptor, LinkDecryptor

STORE_LIMIT: int

class Mix:
    priv_comp: Bn
    pub_comp: EcPt
    incoming: socket
    next_addr: AddressTuple
    mix_addr: AddressTuple

    request_link_encryptor: LinkEncryptor
    response_link_encryptor: LinkEncryptor
    request_link_decryptor: LinkDecryptor
    response_link_decryptor: LinkDecryptor

    check_responses: bool

    def __init__(self, private_key: Bn, own_address: AddressTuple, next_address: AddressTuple, check_responses: bool) -> None: ...
    def handle_mix_fragment(self, payload: bytes) -> None: ...
    def handle_response(self, payload: bytes) -> None: ...
    def run(self) -> None: ...
