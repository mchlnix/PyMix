from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Ciphers.Cipher import Cipher


def default_cipher(keys, iv=bytes(AES.block_size)):
    encryptors = []
    decryptors = []

    for key in keys:
        encryptors.append(AES.new(key.encode("ascii"), AES.MODE_CBC, IV=iv))
        decryptors.append(AES.new(key.encode("ascii"), AES.MODE_CBC, IV=iv))

    encryptors.reverse()

    return CBC(encryptors, decryptors, AES.block_size)


def gen_key():
    return get_random_bytes(AES.key_size[0])


def gen_iv():
    return CBC.gen_iv()


class CBC(Cipher):
    @staticmethod
    def gen_iv(length=AES.block_size):
        return get_random_bytes(length)

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

    @staticmethod
    def gen_key():
        return gen_key()

    def encrypt_with_data(self, plain_text, additional_data):
        for cipher, data in zip(self.encryptors, additional_data):
            plain_text = cipher.encrypt(get_random_bytes(self.iv_size) + data + plain_text)

        return plain_text
