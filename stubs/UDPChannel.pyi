from selectors import DefaultSelector
from socket import socket
from typing import List, Dict, ClassVar, Tuple

from petlib.bn import Bn
from petlib.ec import EcPt
from sphinxmix import SphinxParams

from MixMessage import MixMessage, MixMessageStore, FragmentGenerator
from Types import AddressTuple

params: SphinxParams
params_dict: Dict[Tuple[int, int], SphinxParams]

class ChannelEntry:
    out_chan_list: ClassVar[List[int]]
    to_mix: ClassVar[List[bytes]]
    to_client: ClassVar[List[bytes]]
    table: ClassVar[Dict[int, ChannelEntry]]

    src_addr: AddressTuple
    dest_addr: AddressTuple
    chan_id: int
    b_chan_id: bytes

    pub_comps: List[EcPt]
    sym_keys: List[bytes]

    packets: List[FragmentGenerator]
    mix_msg_store: MixMessageStore
    allowed_to_send: bool

    def __init__(self, src_addr: AddressTuple, dest_addr: AddressTuple, pub_comps: List[EcPt]) -> None: ...
    def chan_init_msg(self) -> bytes: ...
    def get_init_fragment(self) -> bytes: ...
    def get_data_fragment(self) -> bytes: ...
    def clean_generator_list(self): -> None: ...
    def chan_confirm_msg(self) -> None: ...
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
    key: bytes

    initialized: bool

    def __init__(self, in_chan_id: int) -> None: ...
    def forward_request(self, request: bytes) -> None: ...
    def forward_response(self, response: bytes) -> None: ...
    def parse_channel_init(self, channel_init: bytes, priv_comp: Bn) -> None: ...

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
    mix_msg_store: MixMessageStore

    def __init__(self, in_chan_id:int) -> None: ...
    def recv_request(self, request: bytes)-> None: ...
    def recv_response(self) -> None: ...
    def parse_channel_init(self, channel_init: bytes) -> None: ...
    def send_chan_confirm(self) -> None: ...

    @staticmethod
    def random_socket() -> socket: ...
