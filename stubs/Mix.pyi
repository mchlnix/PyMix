from socket import socket
from typing import Any, List

from Types import AddressTuple
from petlib.bn import Bn

STORE_LIMIT: int

class Mix:
    priv_comp: Bn
    pub_comp: Any
    incoming: socket
    next_addr: AddressTuple
    mix_addr: AddressTuple

    req_link_counter: int
    res_link_counter: int
    req_replay_window: List[int]
    res_replay_window: List[int]

    def get_outgoing_chan_id(self, in_chan_id: int) -> int: ...
    def handle_mix_fragment(self, payload: bytes) -> None: ...
    def handle_response(self, payload: bytes) -> None: ...
    def run(self) -> None: ...
