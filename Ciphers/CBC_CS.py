"""CBC_CS is a constant size variation of the mix encryption using CBC. The
algorithm is used in the same way, but instead of inflating the size of the
mix fragment when encrypting and deflating the size when decrypting, the size
is kept constant.
This works by encrypting as normal and assuming the final size, inflated by
encryption, is the one wanted by the user. That means the given data is
of size: wanted_size - encrypt_iterations * iv_size. Since the amount of
iterations is dependent on the number of keys given by the user at time of
instantiation and the IV size is known or explicitely given by the user, it is
trivial for them to calculate the necessary size their data has to have in
order to have a desired size after encryption.
At the decryption step the first most block is still discarded, but is replaced
by a block of random bytes appended to the decrypted packet. It is left to the
user to either communicate to the ultimate receiver of the decrypted data the
number of random bytes to discard or to encode that information or the length
of the actual data inside the sent data itself."""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Ciphers.CBC import CBC


def default_cipher(keys):
    encryptors = []
    decryptors = []

    for key in keys:
        encryptors.append(AES.new(key.encode("ascii"), AES.MODE_CBC))
        decryptors.append(AES.new(key.encode("ascii"), AES.MODE_CBC))

    encryptors.reverse()

    return CBC_CS(encryptors, decryptors, AES.block_size)


class CBC_CS(CBC):
    def __init__(self, encryptors, decryptors, iv_size):
        CBC.__init__(self, encryptors, decryptors, iv_size)

    def decrypt(self, data):
        """Removes the first block, with every decryption step and appends as
        many random bytes to the end to keep the data length constant."""

        for cipher in self.decryptors:
            data = (cipher.decrypt(data)[self.iv_size:] +
                    get_random_bytes(self.iv_size))

        return data
