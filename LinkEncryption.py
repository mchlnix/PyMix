from Counter import Counter
from ReplayDetection import ReplayDetector
from constants import LINK_CTR_START, CTR_PREFIX_LEN, LINK_HEADER_LEN, GCM_MAC_LEN, CHAN_ID_SIZE, MSG_TYPE_FLAG_LEN,\
    RESERVED_LEN
from util import cut, gcm_cipher, b2i, get_random_bytes


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
        cipher = gcm_cipher(self.key, int(self.counter))

        # ctr encrypt the header with a random link counter prefix
        header, mac = cipher.encrypt_and_digest(chan_id + ctr_prefix + msg_type + reserved)

        return bytes(self.counter) + header + mac + payload


class LinkDecryptor:
    def __init__(self, link_key):
        self.key = link_key
        self.replay_detector = ReplayDetector()

    def decrypt(self, cipher_text):
        b_link_ctr, header, mac, fragment = cut(cipher_text, CTR_PREFIX_LEN,
                                                LINK_HEADER_LEN, GCM_MAC_LEN)

        link_ctr = b2i(b_link_ctr)

        cipher = gcm_cipher(self.key, link_ctr)

        plain_header = cipher.decrypt_and_verify(header, mac)

        chan_id, msg_ctr, msg_type, _ = cut(
            plain_header, CHAN_ID_SIZE, CTR_PREFIX_LEN, MSG_TYPE_FLAG_LEN)

        #self.replay_detector.check_replay_window(link_ctr)

        return b2i(chan_id), msg_ctr, fragment, msg_type
