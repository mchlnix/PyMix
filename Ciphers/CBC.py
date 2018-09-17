from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Ciphers.Cipher import Cipher


def default_cipher(keys):
    encryptors = []
    decryptors = []

    for key in keys:
        encryptors.append(AES.new(key.encode("ascii"), AES.MODE_CBC, IV=bytes(16)))
        decryptors.append(AES.new(key.encode("ascii"), AES.MODE_CBC, IV=bytes(16)))

    encryptors.reverse()

    return CBC(encryptors, decryptors, AES.block_size)


class CBC(Cipher):
    def __init__(self, encryptors, decryptors, iv_size):
        Cipher.__init__(self, encryptors, decryptors)
        self.iv_size = iv_size

    def decrypt(self, data):
        for cipher in self.decryptors:
            data = cipher.decrypt(data)[self.iv_size:]

        return data

    def encrypt(self, data):
        for cipher in self.encryptors:
            data = cipher.encrypt(get_random_bytes(self.iv_size) + data)

        return data
