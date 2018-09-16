from Crypto.Cipher import AES

from Ciphers.Cipher import Cipher


def default_cipher(keys):
    encryptors = []
    decryptors = []

    for key in keys:
        encryptors.append(AES.new(key.encode("ascii"), AES.MODE_ECB))
        decryptors.append(AES.new(key.encode("ascii"), AES.MODE_ECB))

    encryptors.reverse()

    return ECB(encryptors, decryptors)


class ECB(Cipher):
    def __init__(self, encryptors, decryptors):
        Cipher.__init__(self, encryptors, decryptors)

    def encrypt(self, data):
        for cipher in self.encryptors:
            data = cipher.encrypt(data)

        return data

    def decrypt(self, data):
        for cipher in self.decryptors:
            data = cipher.decrypt(data)

        return data
