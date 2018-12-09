from constants import LINK_CTR_START, REPLAY_WINDOW_SIZE
from util import link_encrypt, link_decrypt, check_replay_window


class LinkEncryptor:
    def __init__(self, link_key):
        self.key = link_key
        self.counter = LINK_CTR_START

    def encrypt(self, plain_text):
        self.counter += 1
        return link_encrypt(self.key, self.counter, plain_text)


class LinkDecryptor:
    def __init__(self, link_key):
        self.key = link_key
        self.counter = LINK_CTR_START
        self.replay_window = [LINK_CTR_START] * REPLAY_WINDOW_SIZE

    def decrypt(self, cipher_text):
        link_ctr, *plain_text = link_decrypt(self.key, cipher_text)
        check_replay_window(self.replay_window, link_ctr)

        return plain_text
