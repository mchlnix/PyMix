from ReplayDetection import ReplayDetector
from constants import LINK_CTR_START
from util import link_encrypt, link_decrypt


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
        self.replay_detector = ReplayDetector()

    def decrypt(self, cipher_text):
        link_ctr, *plain_text = link_decrypt(self.key, cipher_text)
        self.replay_detector.check_replay_window(link_ctr)

        return plain_text
