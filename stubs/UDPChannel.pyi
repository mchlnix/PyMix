from selectors import DefaultSelector
from socket import socket
from typing import List, Dict, ClassVar, Optional, Union

from Types import AddressTuple
from petlib.bn import Bn
from petlib.ec import EcPt

from Counter import Counter
from MixMessage import MixMessage, MixMessageStore, FragmentGenerator
from ReplayDetection import ReplayDetector


def check_for_timed_out_channels(channel_table: Dict[int, Union[ChannelEntry, ChannelMid, ChannelExit]],
                                 timeout:Optional[int]=...,
                                 log_prefix:Optional[str]=... ) -> List[int]: ...

def create_packet(channel_id: int, message_type: bytes, message_counter: Union[bytes, Counter], payload: bytes) -> bytes: ...

class ChannelEntry:
    out_chan_list: ClassVar[List[int]]
    to_mix: ClassVar[List[bytes]]
    to_client: ClassVar[List[bytes]]
    table: ClassVar[Dict[int, ChannelEntry]]

    src_addr: AddressTuple
    dest_addr: AddressTuple
    chan_id: int

    pub_comps: List[EcPt]
    req_sym_keys: List[bytes]
    res_sym_keys: List[bytes]
    request_counter: Counter
    replay_detector: ReplayDetector

    packets: List[FragmentGenerator]
    mix_msg_store: MixMessageStore
    last_interaction: float
    allowed_to_send: bool

    def __init__(self, src_addr: AddressTuple, dest_addr: AddressTuple, pub_comps: List[EcPt]) -> None: ...
    def can_send(self) -> bool: ...
    def request(self, request: bytes) -> None: ...
    def response(self, response: bytes) -> None: ...
    def get_message(self) -> bytes: ...
    def get_completed_responses(self) -> List[MixMessage]: ...
    def _get_init_message(self) -> bytes: ...
    def _get_data_message(self) -> bytes: ...
    def _get_init_fragment(self) -> bytes: ...
    def _get_data_fragment(self) -> bytes: ...
    def _clean_generator_list(self) -> None: ...
    def _chan_confirm_msg(self) -> None: ...
    def _make_request_fragments(self, request: bytes) -> None: ...
    def _receive_response_fragment(self, response: bytes) -> None: ...

    def _encrypt_fragment(self, fragment: bytes) -> bytes: ...
    def _decrypt_fragment(self, fragment: bytes) -> bytes: ...

    def __str__(self) -> str: ...

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
    req_key: bytes
    res_key: bytes

    request_replay_detector: ReplayDetector
    response_replay_detector: ReplayDetector

    check_responses: bool

    last_interaction: float

    initialized: bool

    def __init__(self, in_chan_id: int, check_responses: bool) -> None: ...
    def forward_request(self, request: bytes) -> None: ...
    def forward_response(self, response: bytes) -> None: ...
    def parse_channel_init(self, channel_init: bytes, priv_comp: Bn) -> None: ...

    def __str__(self) -> str: ...

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

    last_interaction: float
    response_counter: Counter

    def __init__(self, in_chan_id:int) -> None: ...
    def recv_request(self, request: bytes)-> None: ...
    def recv_response(self, response: bytes) -> None: ...
    def parse_channel_init(self, channel_init: bytes) -> None: ...
    def send_chan_confirm(self) -> None: ...

    def __str__(self) -> str: ...

    @staticmethod
    def random_socket() -> socket: ...
