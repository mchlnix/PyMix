from typing import List

from Ciphers.CBC import CBC


def default_cipher(keys: List[bytes], iv: bytes) -> CBC_CS: ...


class CBC_CS(CBC):
    def __init__(self, encryptors: list, decryptors: list, iv_size: int) -> None:
        super().__init__(encryptors, decryptors, iv_size)
        ...
    def encrypt(self, data: bytes) -> bytes: ...
    def decrypt(self, data: bytes) -> bytes: ...
    def encrypt_with_data(self, plain_text: bytes, additional_data: List[bytes]) -> bytes: ...
    def prepare_data(self, data: bytes) -> bytes: ...
    def finalize_data(self, data: bytes) -> bytes: ...
