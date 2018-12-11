# MsgV3 format
from MsgV3 import process, gen_init_msg, params
from util import get_random_bytes, gen_sym_key


def test_gen_init_msg():
    priv1 = params.group.gensecret()
    priv2 = params.group.gensecret()
    priv3 = params.group.gensecret()

    pub1 = params.group.expon_base([priv1])
    pub2 = params.group.expon_base([priv2])
    pub3 = params.group.expon_base([priv3])

    passes = 100

    for _ in range(passes):
        chan_keys = [gen_sym_key(), gen_sym_key(), gen_sym_key()]
        payload = get_random_bytes(100)

        proc_chan_keys = []

        message = gen_init_msg([pub1, pub2, pub3], chan_keys, payload)

        for priv_key in [priv1, priv2, priv3]:
            proc_chan_key, proc_payload, message = process(priv_key, message)

            proc_chan_keys.append(proc_chan_key)

        assert chan_keys == proc_chan_keys
        assert payload == proc_payload
