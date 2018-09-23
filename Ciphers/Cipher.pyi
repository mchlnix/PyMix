from typing import List


class Cipher:
    encryptors: List[object]
    decryptors: List[object]
    stages: int
    def __init__(self, encryptors: List[object], decryptors: List[object]) -> None: ...
    def decrypt(self, data: bytes) -> bytes: ...
    def encrypt(self, data: bytes) -> bytes: ...
    def prepare_data(self, data: bytes) -> bytes: ...
    def finalize_data(self, data: bytes) -> bytes: ...
    def encrypt_with_data(self, plain_text: bytes, additional_data: List) -> bytes: ...


def default_cipher(keys: List[bytes], iv: int) -> Cipher: ...
def gen_iv() -> bytes: ...