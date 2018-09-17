"""CBC_CS is a constant size variation of the mix encryption using CBC. The
algorithm is used in the same way, but instead of inflating the size of the
mix fragment when encrypting and deflating the size when decrypting, the size
is kept constant.
This works by assuming, that the user, knowing how many random blocks will be
added by the encryption iteration, will put as many random blocks at the end of
the plain text, that is encrypted. Since the amount of iterations is dependent
on the number of keys given by the user at time of instantiation and the IV
size is known or explicitely given by the user, it is trivial for them to
calculate the necessary size of the data to be appended.
The encryption is then adding a random block as normal, but also removing a
block from the end of the plain text, thereby keeping the size constant.
At the decryption step the first most block is still discarded, but is replaced
by a block of random bytes appended to the decrypted packet. It is left to the
user to either communicate to the ultimate receiver of the decrypted data the
number of random bytes to discard or to encode that information or the length
of the actual data inside the sent data itself.

Example for 3 iterations and IV size of 16:

    # initial plain data
    plain

    # after prepare_data
    plain + r(48)

    # encryption
    enc(r(16) + plain) + r(32)
    enc(r(16) + enc(r(16) + plain)) + r(16)
    enc(r(16) + enc(r(16) + enc(r(16) + plain)))

    # decryption
    dec(enc(r(16) + enc(r(16) + enc(r(16) + plain)))) =
    enc(r(16) + enc(r(16) + plain)) + r(16)
    enc(r(16) + plain) + r(32)
    plain + r(48)

    # plain data after finalize_data
    plain

"""
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
