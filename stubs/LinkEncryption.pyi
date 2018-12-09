from typing import List, Tuple


class LinkEncryptor:
    key: bytes
    counter: int

    def __init__(self, link_key: bytes) -> None: ...
    def encrypt(self, plain_text: bytes) -> bytes: ...

class LinkDecryptor:
    key: bytes
    replay_window: List[int]

    def __init__(self, link_key: bytes) -> None:...
    def decrypt(self, cipher_text: bytes) -> Tuple[int, bytes, bytes, bytes]: ...
