from typing import Union


class MD5Hash(object):
    digest_size: int
    block_size: int
    oid: str

    def __init__(self, data: Union[bytes, bytearray, memoryview]) -> None: ...
    def update(self, data: Union[bytes, bytearray, memoryview]) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> MD5Hash: ...
    def new(self, data: Union[bytes, bytearray, memoryview]) -> MD5Hash: ...

def new(data: Union[bytes, bytearray, memoryview]) -> MD5Hash: ...

digest_size: int
block_size: int