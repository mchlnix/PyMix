from petlib.ec import EcPt

from constants import SYM_KEY_LEN, SPHINX_PARAMS, MIX_COUNT
from util import ctr_cipher, cut, gen_sym_key

params = SPHINX_PARAMS


def gen_init_msg(pub_mix_keys, channel_keys, payload):
    assert len(pub_mix_keys) == len(channel_keys)

    y_mix_1, y_mix_2, y_mix_3 = pub_mix_keys

    x_msg_1 = params.group.gensecret()
    y_msg_1 = params.group.expon_base([x_msg_1])
    k_disp_1 = params.group.expon(y_mix_1, [x_msg_1])
    blind_1 = gen_blind(k_disp_1)

    x_msg_2 = params.group.expon(x_msg_1, [blind_1])
    k_disp_2 = params.group.expon(y_mix_2, [x_msg_2])
    blind_2 = gen_blind(k_disp_2)

    x_msg_3 = params.group.expon(x_msg_2, [blind_2])
    k_disp_3 = params.group.expon(y_mix_3, [x_msg_3])

    chan_key_onion = gen_sym_key() * 3
    payload_onion = payload

    for k_disp, k_chan in zip([k_disp_3, k_disp_2, k_disp_1], reversed(channel_keys)):
        cipher = ctr_cipher(params.get_aes_key(k_disp), 0)

        chan_key_onion = cipher.encrypt(k_chan + chan_key_onion[0:-SYM_KEY_LEN])

        payload_onion = cipher.encrypt(payload_onion)

    return y_msg_1.export() + chan_key_onion + payload_onion


def gen_blind(secret):
    # since the group_elem is used in the generation of secret, there is no need for it to be used
    return params.hb(params.get_aes_key(secret))


def process(priv_mix_key, message):
    # first stage

    b_y_msg, chan_key_onion, payload_onion = cut(message, 29, MIX_COUNT * SYM_KEY_LEN)

    y_msg = EcPt.from_binary(b_y_msg, params.group.G)
    k_disp = params.group.expon(y_msg, [priv_mix_key])

    cipher = ctr_cipher(params.get_aes_key(k_disp), 0)

    k_chan, chan_key_onion = cut(cipher.decrypt(chan_key_onion), SYM_KEY_LEN)

    # pad onion
    chan_key_onion += gen_sym_key()

    payload_onion = cipher.decrypt(payload_onion)

    blind_1 = gen_blind(k_disp)
    y_msg_2 = params.group.expon(y_msg, [blind_1])

    message = y_msg_2.export() + chan_key_onion + payload_onion

    return k_chan, payload_onion, message
