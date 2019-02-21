from petlib.cipher import Cipher
from petlib.ec import EcPt
from sphinxmix.SphinxParams import SphinxParams

from constants import SYM_KEY_LEN, MIX_COUNT, GROUP_ELEMENT_LEN, CTR_PREFIX_LEN, NONCE_LEN
from util import ctr_cipher, cut, gen_sym_key, i2b, get_random_bytes

params = SphinxParams()

aes = Cipher("AES-128-CTR")


def group_expon(exponent):
    return params.group.expon_base([exponent])


def gen_priv_key():
    return params.group.gensecret()


def get_pub_key(private_key):
    return group_expon(private_key)


def gen_init_msg(pub_mix_keys, message_counter, request_channel_keys, response_channel_keys, payload):
    assert len(pub_mix_keys) == len(request_channel_keys)

    ctr = i2b(message_counter, CTR_PREFIX_LEN) + bytes(NONCE_LEN - CTR_PREFIX_LEN)
    ctr_blind = gen_blind(ctr)

    y_mix_1, y_mix_2, y_mix_3 = pub_mix_keys

    x_msg_1 = params.group.gensecret()
    y_msg_1 = params.group.expon_base([x_msg_1])
    k_disp_1 = params.group.expon(y_mix_1, [x_msg_1])
    k_disp_1 = params.group.expon(k_disp_1, [ctr_blind])
    blind_1 = gen_blind(k_disp_1)

    x_msg_2 = params.group.expon(x_msg_1, [blind_1])
    k_disp_2 = params.group.expon(y_mix_2, [x_msg_2])
    k_disp_2 = params.group.expon(k_disp_2, [ctr_blind])
    blind_2 = gen_blind(k_disp_2)

    x_msg_3 = params.group.expon(x_msg_2, [blind_2])
    k_disp_3 = params.group.expon(y_mix_3, [x_msg_3])
    k_disp_3 = params.group.expon(k_disp_3, [ctr_blind])

    chan_key_onion = get_random_bytes(MIX_COUNT * 2 * SYM_KEY_LEN)
    payload_onion = payload

    for k_disp, k_chan_req, k_chan_res in zip([k_disp_3, k_disp_2, k_disp_1], reversed(request_channel_keys), reversed(response_channel_keys)):
        key = params.get_aes_key(k_disp)

        cipher = aes.enc(key, ctr)

        chan_key_onion = cipher.update(k_chan_req + k_chan_res + chan_key_onion[0:-2 * SYM_KEY_LEN])

        cipher = aes.enc(key, ctr)

        payload_onion = cipher.update(payload_onion)

    return y_msg_1.export() + chan_key_onion + payload_onion


def gen_blind(secret):
    if isinstance(secret, EcPt):
        return params.hb(params.get_aes_key(secret))
    else:
        return params.hb(secret)


def process(priv_mix_key, message_counter, message):
    y_msg, chan_key_onion, payload_onion = cut_init_message(message)

    ctr = i2b(message_counter, CTR_PREFIX_LEN) + bytes(NONCE_LEN - CTR_PREFIX_LEN)

    ctr_blind = gen_blind(ctr)

    k_disp = params.group.expon(y_msg, [priv_mix_key])
    k_disp = params.group.expon(k_disp, [ctr_blind])

    key = params.get_aes_key(k_disp)
    cipher = ctr_cipher(key, message_counter)

    k_chan_req, k_chan_res, chan_key_onion = cut(cipher.update(chan_key_onion), SYM_KEY_LEN, SYM_KEY_LEN)

    chan_key_onion += gen_sym_key()
    chan_key_onion += gen_sym_key()

    cipher = ctr_cipher(key, message_counter)

    payload_onion = cipher.update(payload_onion)

    blind_1 = gen_blind(k_disp)
    y_msg_2 = params.group.expon(y_msg, [blind_1])

    message = y_msg_2.export() + chan_key_onion + payload_onion

    return k_chan_req, k_chan_res, payload_onion, message


def cut_init_message(message):
    group_element, channel_key_onion, payload_onion = cut(message, GROUP_ELEMENT_LEN, MIX_COUNT * 2 * SYM_KEY_LEN)

    return EcPt.from_binary(group_element, params.group.G), channel_key_onion, payload_onion
