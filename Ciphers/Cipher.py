from Crypto.Random import get_random_bytes


# noinspection PyUnusedLocal
def default_cipher(keys, iv):
    raise NotImplementedError()


class Cipher:
    def __init__(self, encryptors, decryptors):
        self.encryptors = encryptors
        self.decryptors = decryptors
        self.stages = len(self.encryptors)

    def encrypt(self, data):
        raise NotImplementedError("Cipher.encrypt(data)")

    def decrypt(self, data):
        raise NotImplementedError("Cipher.decrypt(data)")

    @staticmethod
    def prepare_data(data):
        return data

    @staticmethod
    def finalize_data(data):
        return data

    @staticmethod
    def gen_iv():
        return bytes(16)

    @staticmethod
    def gen_key():
        return get_random_bytes(16)

    def encrypt_with_data(self, plain, additional_data):
        raise NotImplementedError
