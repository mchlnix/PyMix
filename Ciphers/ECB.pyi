from typing import List

from Crypto.Cipher import AES

from Ciphers.Cipher import Cipher


class ECB(Cipher):
    def __init__(self, encryptors: List[AES], decryptors: List[AES]):
        super().__init__(encryptors, decryptors)
        ...

    def encrypt(self, data: bytes) -> bytes: ...
    def decrypt(self, data: bytes) -> bytes: ...