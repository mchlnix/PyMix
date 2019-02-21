from petlib.cipher import Cipher

from Counter import Counter
from ReplayDetection import ReplayDetector
from constants import LINK_CTR_START, CTR_PREFIX_LEN, LINK_HEADER_LEN, GCM_MAC_LEN, CHAN_ID_SIZE, MSG_TYPE_FLAG_LEN, \
    RESERVED_LEN, NONCE_LEN
from util import cut, b2i, get_random_bytes

aes_gcm = Cipher("aes-128-gcm")


class LinkEncryptor:
    def __init__(self, link_key):
        self.key = link_key
        self.counter = Counter(LINK_CTR_START)

    def encrypt(self, plain_text):
        self.counter.count()

        chan_id, msg_type, ctr_prefix, payload = cut(
            plain_text, CHAN_ID_SIZE, MSG_TYPE_FLAG_LEN, CTR_PREFIX_LEN)

        reserved = get_random_bytes(RESERVED_LEN)

        # use all 0s as link key, since they can not be exchanged yet
        ctr = bytes(self.counter) + bytes(NONCE_LEN - CTR_PREFIX_LEN)
        cipher = aes_gcm.enc(self.key, ctr)

        # ctr encrypt the header with a random link counter prefix
        header = cipher.update(chan_id + ctr_prefix + msg_type + reserved)
        cipher.finalize()
        mac = cipher.get_tag(GCM_MAC_LEN)

        return bytes(self.counter) + header + mac + payload


class LinkDecryptor:
    def __init__(self, link_key):
        self.key = link_key
        self.replay_detector = ReplayDetector()

    def decrypt(self, cipher_text):
        b_link_ctr, header, mac, fragment = cut(cipher_text, CTR_PREFIX_LEN,
                                                LINK_HEADER_LEN, GCM_MAC_LEN)

        ctr = b_link_ctr + bytes(NONCE_LEN - CTR_PREFIX_LEN)
        cipher = aes_gcm.dec(self.key, ctr)

        plain_header = cipher.update(header)
        cipher.set_tag(mac)
        cipher.finalize()

        chan_id, msg_ctr, msg_type, _ = cut(
            plain_header, CHAN_ID_SIZE, CTR_PREFIX_LEN, MSG_TYPE_FLAG_LEN)

        #self.replay_detector.check_replay_window(link_ctr)

        return b2i(chan_id), msg_ctr, fragment, msg_type
