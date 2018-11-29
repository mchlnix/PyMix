from petlib.ec import EcPt

from constants import SYM_KEY_LEN
from util import ctr_cipher, cut, gen_sym_key


class MsgFactory:
    def __init__(self, pub_mix_keys, params):
        self.pub_mix_keys = pub_mix_keys
        self.params = params

    def gen_init_msg(self, channel_keys, payload):
        assert len(self.pub_mix_keys) == len(channel_keys)

        y_mix_1, y_mix_2, y_mix_3 = self.pub_mix_keys

        x_msg_1 = self.params.group.gensecret()
        y_msg_1 = self.params.group.expon_base([x_msg_1])
        k_disp_1 = self.params.group.expon(y_mix_1, [x_msg_1])
        blind_1 = self.gen_blind(y_msg_1, k_disp_1)

        x_msg_2 = self.params.group.expon(x_msg_1, [blind_1])
        y_msg_2 = self.params.group.expon(y_msg_1, [blind_1])
        k_disp_2 = self.params.group.expon(y_mix_2, [x_msg_2])
        blind_2 = self.gen_blind(y_msg_2, k_disp_2)

        x_msg_3 = self.params.group.expon(x_msg_2, [blind_2])
        k_disp_3 = self.params.group.expon(y_mix_3, [x_msg_3])

        chan_key_onion = gen_sym_key() * 3
        payload_onion = payload

        for k_disp, k_chan in zip([k_disp_3, k_disp_2, k_disp_1], reversed(channel_keys)):
            cipher = ctr_cipher(self.params.get_aes_key(k_disp), 0)

            chan_key_onion = cipher.encrypt(k_chan + chan_key_onion[0:-SYM_KEY_LEN])

            payload_onion = cipher.encrypt(payload_onion)

        return y_msg_1.export() + chan_key_onion + payload_onion

    def gen_blind(self, group_elem, secret):
        # since the group_elem is used in the generation of secret, there is no need for it to be used
        return self.params.hb(self.params.get_aes_key(secret))

    def process(self, priv_mix_keys, message):
        x_mix_1, x_mix_2, x_mix_3 = priv_mix_keys

        # first stage

        b_y_msg_1, chan_key_onion, payload_onion = cut(message, 29, 48)

        y_msg_1 = EcPt.from_binary(b_y_msg_1, self.params.group.G)
        k_disp_1 = self.params.group.expon(y_msg_1, [x_mix_1])

        cipher = ctr_cipher(self.params.get_aes_key(k_disp_1), 0)

        k_chan_1, chan_key_onion = cut(cipher.decrypt(chan_key_onion), SYM_KEY_LEN)

        # pad onion
        chan_key_onion += gen_sym_key()

        payload_onion = cipher.decrypt(payload_onion)

        blind_1 = self.gen_blind(y_msg_1, k_disp_1)
        y_msg_2 = self.params.group.expon(y_msg_1, [blind_1])

        message = y_msg_2.export() + chan_key_onion + payload_onion

        # second stage

        b_y_msg_2, chan_key_onion, payload_onion = cut(message, 29, 48)
        y_msg_2 = EcPt.from_binary(b_y_msg_2, self.params.group.G)

        k_disp_2 = self.params.group.expon(y_msg_2, [x_mix_2])

        cipher = ctr_cipher(self.params.get_aes_key(k_disp_2), 0)

        k_chan_2, chan_key_onion = cut(cipher.decrypt(chan_key_onion), SYM_KEY_LEN)

        # pad onion
        chan_key_onion += gen_sym_key()

        payload_onion = cipher.decrypt(payload_onion)

        blind_2 = self.gen_blind(y_msg_2, k_disp_2)
        y_msg_3 = self.params.group.expon(y_msg_2, [blind_2])

        message = y_msg_3.export() + chan_key_onion + payload_onion

        # last stage

        b_y_msg_3, chan_key_onion, payload_onion = cut(message, 29, 48)
        y_msg_3 = EcPt.from_binary(b_y_msg_3, self.params.group.G)

        k_disp_3 = self.params.group.expon(y_msg_3, [x_mix_3])

        cipher = ctr_cipher(self.params.get_aes_key(k_disp_3), 0)

        k_chan_3, _ = cut(cipher.decrypt(chan_key_onion), SYM_KEY_LEN)

        payload = cipher.decrypt(payload_onion)

        return k_chan_1, k_chan_2, k_chan_3, payload




