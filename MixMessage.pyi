from typing import List, Tuple, Dict

from Types import AddressTuple

FRAG_SIZE: int
ID_SIZE: int
FRAG_COUNT_SIZE: int
FRAG_INDEX_SIZE: int
PADDING_SIZE: int
DEST_IP_SIZE: int
DEST_PORT_SIZE: int
HEADER_SIZE: int
PAYLOAD_SIZE: int
MAX_FRAG_COUNT: int
HIGHEST_ID: int
LOWEST_ID: int

def make_fragments(packet: bytes, dest_addr: AddressTuple) -> List[bytearray]: ...
def _read_int(data: bytes, start: int, length: int) -> Tuple[int, int]: ...

class MixMessageStore:
    packets: Dict[int, MixMessage]

    def __init__(self) -> None: ...
    def parse_fragment(self, raw_frag: bytes) -> MixMessage: ...
    def completed(self) -> List[MixMessage]: ...
    def remove(self) -> None: ...
    def remove_completed(self) -> None: ...


class MixMessage:
    fragments: Dict[int, bytes]
    id: int
    frag_count: int
    dest: AddressTuple
    pad_size: int
    payload_size: int
    def __init__(self, msg_id: int) -> None: ...
    def add_fragment(self, frag_index: int, payload: bytes) -> None: ...
    def complete(self) -> bool: ...
    def payload(self) -> bytes: ...
    def __str__(self) -> str: ...
