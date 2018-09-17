from typing import Dict, List

from Types import AddressTuple

UDP_MTU: int
MIN_PORT: int
MAX_PORT: int

class ExitPoint:
    mix_addr: AddressTuple
    store: MixMessageStore
    sock_table: TwoWayTable
    padding_dict: Dict[int, int]
    ports: List[int]
    sock_sel: DefaultSelector
    sock_to_mix: socket

    def random_socket(self) -> socket: ...
    def handle_mix_fragment(self, packet: bytes) -> None: ...
    def handle_response(self, sock: socket) -> None: ...
    def run(self) ->  None: ...
