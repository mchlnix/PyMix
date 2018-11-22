from typing import List
from socket import socket

from Types import AddressTuple


class ExitPoint:
    mix_addr: AddressTuple
    sock_to_mix: socket

    link_counter: int
    replay_window: List[int]

    def __init__(self, own_addr: AddressTuple) -> None: ...
    def run(self) ->  None: ...
