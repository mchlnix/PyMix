from sys import path
from os.path import realpath

script_dir = "/".join(realpath(__file__).split("/")[:-1])
path.append(script_dir + "/..")

from Cryptodome.Random import get_random_bytes

from util import gen_sym_key
from constants import SPHINX_PARAMS
from MsgV3 import process, gen_init_msg


params = SPHINX_PARAMS

priv1 = params.group.gensecret()
priv2 = params.group.gensecret()
priv3 = params.group.gensecret()

pub1 = params.group.expon_base([priv1])
pub2 = params.group.expon_base([priv2])
pub3 = params.group.expon_base([priv3])

passes = 100

for i in range(passes):
    chan_keys = [gen_sym_key(), gen_sym_key(), gen_sym_key()]
    payload = get_random_bytes(100)

    proc_chan_keys = []
    proc_payload = b""

    message = gen_init_msg([pub1, pub2, pub3], chan_keys, payload)

    for priv_key in [priv1, priv2, priv3]:
        proc_chan_key, proc_payload, message = process(priv_key, message)

        proc_chan_keys.append(proc_chan_key)

    assert chan_keys == proc_chan_keys
    assert payload == proc_payload

    print("\r{}/{}".format(i+1, passes), end="")

print("\rSuccess")
