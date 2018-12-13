from typing import List, Dict, Tuple

from Types import AddressTuple
from petlib.bn import Bn
from petlib.ec import EcPt

from LinkEncryption import LinkEncryptor, LinkDecryptor
from UDPChannel import ChannelEntry


class EntryPoint:
    own_addr: AddressTuple
    mix_addr: AddressTuple
    ips2id: Dict[Tuple[AddressTuple, AddressTuple], int]
    pub_comps: List[EcPt]
    socket: socket

    link_decryptor: LinkDecryptor
    link_encryptor: LinkEncryptor

    def __init__(self, listen_addr: AddressTuple, addr_to_mix: AddressTuple): ...
    def set_keys(self, keys: List[Bn]) -> None: ...
    def handle_mix_response(self, response: bytes) -> None: ...
    def handle_client_request(self, request: bytes, src_addr: AddressTuple) -> None: ...
    def make_new_channel(self, src_addr: AddressTuple, dest_addr: AddressTuple) -> ChannelEntry: ...
    def send_messages_to_mix(self) -> None: ...
    def run(self) -> None: ...
