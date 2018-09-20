from typing import List, Dict
from socket import socket
from selectors import DefaultSelector

from Ciphers.Cipher import Cipher
from MixMessage import MixMessage, MixMessageStore
from Types import AddressTuple

class ChannelEntry:
    out_chan_list: List[int]
    to_mix: List[bytes]
    id2channel: Dict[int, ChannelEntry]

    src_addr: AddressTuple
    dest_addr: AddressTuple
    chan_id: int
    keys: List[bytes]
    cipher: Cipher
    packers: List[bytes]
    mix_msg_store: MixMessageStore

    def __init__(self, src_addr: AddressTuple, dest_addr: AddressTuple, mix_count: int): ...
    def chan_init_msg(self, mix_cipher: Cipher) -> bytes: ...
    def make_request_fragments(self, request: bytes) -> None: ...
    def recv_response_fragment(self, response: bytes) -> None: ...
    def get_completed_responses(self) -> List[MixMessage]: ...

    @staticmethod
    def random_channel() -> int: ...

class ChannelMid:
    out_chan_list: List[int]
    requests: List[bytes]
    responses: List[bytes]
    out2chan: Dict[int, ChannelMid]
    in2chan: Dict[int, ChannelMid]

    in_chan_id: int
    out_chan_id: int
    cipher: Cipher

    def __init__(self, in_chan_id: int): ...
    def forward_request(self, request: bytes): ...
    def forward_response(self, response: bytes): ...
    def parse_channel_init(self, channel_init: bytes): ...

    @staticmethod
    def random_channel() -> int: ...

class ChannelExit:
    out_ports: List[int]
    sock_sel: DefaultSelector
    to_mix: List[bytes]

    in_chan_id: int
    out_sock: socket
    dest_addr: AddressTuple
    padding: int
    mix_msg_store: MixMessageStore

    def __init__(self, in_chan_id:int): ...
    def recv_request(self, request: bytes): ...
    def recv_response(self):...
    def parse_channel_init(self, channel_init: bytes): ...

    @staticmethod
    def random_socket() -> socket: ...
