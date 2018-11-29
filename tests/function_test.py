from sys import path
from os.path import realpath

script_dir = "/".join(realpath(__file__).split("/")[:-1])
path.append(script_dir + "/..")

from Crypto.Random import get_random_bytes

from util import gen_sym_key
from MsgV3 import MsgFactory
from constants import SPHINX_PARAMS

params = SPHINX_PARAMS

priv1 = params.group.gensecret()
priv2 = params.group.gensecret()
priv3 = params.group.gensecret()

pub1 = params.group.expon_base([priv1])
pub2 = params.group.expon_base([priv2])
pub3 = params.group.expon_base([priv3])

factory = MsgFactory([pub1, pub2, pub3], SPHINX_PARAMS)

passes = 100

for i in range(passes):
    chan_key1 = gen_sym_key()
    chan_key2 = gen_sym_key()
    chan_key3 = gen_sym_key()

    payload = get_random_bytes(100)

    init_msg = factory.gen_init_msg([chan_key1, chan_key2, chan_key3], payload)

    proc_chan_key1, proc_chan_key2, proc_chan_key3, proc_payload = factory.process([priv1, priv2, priv3], init_msg)

    assert chan_key1 == proc_chan_key1
    assert chan_key2 == proc_chan_key2
    assert chan_key3 == proc_chan_key3
    assert payload == proc_payload

    print("\r{}/{}".format(i+1, passes), end="")

print("\rSuccess")
