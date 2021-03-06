from typing import List, Tuple, Dict, ClassVar

FRAG_ID_SIZE: int
DUMMY_FRAG_ID: int

FRAG_COUNT_SIZE: int
FRAG_INDEX_SIZE: int
FRAG_PADDING_SIZE: int
FRAG_HEADER_SIZE: int

MAX_FRAG_COUNT: int

HIGHEST_ID: int
LOWEST_ID: int
SINGLE_FRAGMENT_MESSAGE_ID: int

DATA_FRAG_SIZE: int
INIT_FRAG_SIZE: int

DATA_PACKET_SIZE: int
INIT_PACKET_SIZE: int

class MixMessageStore:
    packets: Dict[int, MixMessage]

    def __init__(self) -> None: ...
    def parse_fragment(self, raw_frag: bytes) -> MixMessage: ...
    def completed(self) -> List[MixMessage]: ...
    def remove(self, msg_id: int) -> None: ...
    def remove_completed(self) -> None: ...


class MixMessage:
    fragments: Dict[int, bytes]
    id: int
    frag_count: int
    payload_size: int
    def __init__(self, msg_id: int) -> None: ...
    def add_fragment(self, frag_index: int, payload: bytes) -> None: ...
    @property
    def complete(self) -> bool: ...
    @property
    def payload(self) -> bytes: ...
    def __str__(self) -> str: ...

FRAG_FLAG_SIZE: int
PADDING_SIZE: int

def how_many_padding_bytes_necessary(padding_len: int) -> int: ...
def bytes_to_padding_length(padding_bytes: bytes) -> int: ...
def padding_length_to_bytes(padding_length: int) -> Tuple[bytes, int]: ...
def parse_fragment(fragment: bytes) -> Tuple[int, bool, int, bytes]: ...

def make_fragment(message_id: int, fragment_number: int, last_fragment: bool, payload: bytes, payload_limit: int) -> bytes: ...
def make_dummy_init_fragment() -> bytes: ...
def make_dummy_data_fragment() -> bytes: ...

class FragmentGenerator:
    PADDING_FLAG: ClassVar[int]
    LAST_FRAG_FLAG: ClassVar[int]
    PADDING_BITMASK: ClassVar[int]
    PADDING_DONE_FLAG: ClassVar[int]

    udp_payload: bytes
    message_id: int
    current_fragment: int

    last_used_message_id: int

    def __init__(self, udp_payload: bytes) -> None: ...
    def get_init_fragment(self) -> bytes: ...
    def get_data_fragment(self) -> bytes: ...
    def _build_fragment(self, payload_limit: int) -> bytes: ...
    def __bool__(self) -> bool: ...