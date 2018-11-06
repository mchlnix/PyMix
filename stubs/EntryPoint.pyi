from typing import List, Dict, Tuple

from Types import AddressTuple

from Crypto.PublicKey.RSA import RsaKey
from MixMessage import MixMessage, MixMessageStore

class EntryPoint:
    own_addr: AddressTuple
    mix_addr: AddressTuple
    mix_msg_store: MixMessageStore
    ips2id: Dict[Tuple[AddressTuple, AddressTuple], int]
    packets: List[bytes]
    mix_ciphers: list
    socket: socket

    def __init__(self, listen_addr: AddressTuple, addr_to_mix: AddressTuple): ...
    def set_keys(self, keys: List[RsaKey]) -> None: ...
    def get_outgoing_chan_id(self, src_addr: AddressTuple, dest_addr: AddressTuple) -> int: ...
    def add_packets_from_mix_message(self, message: MixMessage, dest: AddressTuple, chan_id: int) -> None: ...
    def handle_mix_fragment(self, response: bytes) -> None: ...
    def handle_request(self, request: bytes, src_addr: AddressTuple) -> None: ...
    def run(self) -> None: ...
