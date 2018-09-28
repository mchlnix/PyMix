from typing import List, Sequence, Dict, Tuple
from Types import AddressTuple

def b2i(int_in_bytes: bytes) -> int: ...
def i2b(integer: int, length: int) -> bytes: ...
def i2ip(ip_as_int: int) -> str: ...
def ip2i(ip_as_str: str) -> int: ...
def parse_ip_port(ip_port: str) -> AddressTuple: ...
def padded(byte_seq: bytes, blocksize: int) -> bytes: ...
def prependlength(packet: bytes) -> bytes: ...
def items_from_file(filepath: str) -> List[str]: ...
def read_cfg_file(filepath: str) -> Dict[str, str]: ...
def read_cfg_values(filepath: str) -> List[str]: ...
def partitions(sequence: Sequence, part_size: int) -> int: ...
def partitioned(sequence: Sequence, part_size: int) -> list: ...
def byte_len(integer: int) -> int: ...
def random_channel_id() -> int: ...
def cut(sequence: bytes, cut_point: int) -> Tuple[bytes, bytes]: ...