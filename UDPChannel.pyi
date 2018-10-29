from selectors import DefaultSelector
from socket import socket
from typing import List, Dict, ClassVar

from MixMessage import MixMessage, MixMessageStore
from Types import AddressTuple


class ChannelEntry:
    out_chan_list: ClassVar[List[int]] = []
    to_mix: ClassVar[List[bytes]]
    to_client: ClassVar[List[bytes]]
    table: ClassVar[Dict[int, ChannelEntry]]

    src_addr: AddressTuple
    dest_addr: AddressTuple
    chan_id: int
    keys: List[bytes]
    counters: List[int]
    packers: List[bytes]
    mix_msg_store: MixMessageStore

    def __init__(self, src_addr: AddressTuple, dest_addr: AddressTuple, mix_count: int) -> None: ...
    def chan_init_msg(self, mix_cipher: list) -> bytes: ...
    def make_request_fragments(self, request: bytes) -> None: ...
    def recv_response_fragment(self, response: bytes) -> None: ...
    def get_completed_responses(self) -> List[MixMessage]: ...

    def encrypt_fragment(self, fragment: bytes) -> bytes: ...
    def decrypt_fragment(self, fragment: bytes) -> bytes: ...

    @staticmethod
    def random_channel() -> int: ...

class ChannelMid:
    out_chan_list: ClassVar[List[int]]
    requests: ClassVar[List[bytes]]
    responses: ClassVar[List[bytes]]

    table_out: ClassVar[Dict[int, ChannelMid]]
    table_in: ClassVar[Dict[int, ChannelMid]]

    in_chan_id: int
    out_chan_id: int
    ctr_own: int
    ctr_next: int
    key: bytes

    last_prev_ctrs = List[int]
    last_next_ctrs = List[int]

    def __init__(self, in_chan_id: int) -> None: ...
    def forward_request(self, request: bytes): ...
    def forward_response(self, response: bytes): ...
    @staticmethod
    def _check_replay_window(ctr_list: List[int], ctr: int) -> bool: ...

    def parse_channel_init(self, channel_init: bytes): ...

    @staticmethod
    def random_channel() -> int: ...

class ChannelExit:
    out_ports: ClassVar[List[int]]
    sock_sel: ClassVar[DefaultSelector]
    to_mix: ClassVar[List[bytes]]
    table: ClassVar[Dict[int, ChannelExit]]

    in_chan_id: int
    out_sock: socket
    dest_addr: AddressTuple
    padding: int
    mix_msg_store: MixMessageStore

    def __init__(self, in_chan_id:int) -> None: ...
    def recv_request(self, request: bytes): ...
    def recv_response(self):...
    def parse_channel_init(self, channel_init: bytes): ...

    @staticmethod
    def random_socket() -> socket: ...
