def default_cipher(keys):
    raise NotImplementedError()


class Cipher:
    def __init__(self, encryptors, decryptors):
        self.encryptors = encryptors
        self.decryptors = decryptors

    def encrypt(self, data):
        raise NotImplementedError("Cipher.encrypt(data)")

    def decrypt(self, data):
        raise NotImplementedError("Cipher.decrypt(data)")
