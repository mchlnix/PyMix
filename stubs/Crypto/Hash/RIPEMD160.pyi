from typing import Union


class RIPEMD160Hash(object):
    digest_size: int
    block_size: int
    oid: str
    def __init__(self, data: Union[bytes, bytearray, memoryview]) -> None: ...
    def update(self, data: Union[bytes, bytearray, memoryview]) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> RIPEMD160Hash: ...
    def new(self, data: Union[bytes, bytearray, memoryview]) -> RIPEMD160Hash: ...

def new(data: Union[bytes, bytearray, memoryview]) -> RIPEMD160Hash: ...

digest_size: int
block_size: int
