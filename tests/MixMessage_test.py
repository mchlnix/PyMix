#!/usr/bin/python3

from MixMessage import FragmentGenerator, padding_len_bytes, how_many_padding_bytes_necessary, FRAG_FLAG_SIZE, \
    FRAG_ID_SIZE
from MsgV3 import process, params, gen_init_msg
from constants import FRAG_PAYLOAD_SIZE
from util import i2b, b2i, cut, get_random_bytes, gen_sym_key

assert 1 == how_many_padding_bytes_necessary(1) == how_many_padding_bytes_necessary(2**7)
assert 2 == how_many_padding_bytes_necessary(2**7+1) == how_many_padding_bytes_necessary(2**14)
assert 3 == how_many_padding_bytes_necessary(2**14+1) == how_many_padding_bytes_necessary(2**21)

print("Success - how_many_bytes")

paddings = {0: bytes(0),
            1: i2b(0b1000_0000, 1),
            2: i2b(0b1000_0001, 1),
            127: i2b(0b1111_1110, 1),
            128: i2b(0b1111_1111, 1),
            129: i2b(0b0000_0000_1111_1111, 2),
            130: i2b(0b0000_0001_1000_0000, 2),
            256: i2b(0b0000_0001_1111_1110, 2),
            257: i2b(0b0000_0001_1111_1111, 2),
            258: i2b(0b0000_0010_1000_0000, 2),
            271: i2b(0b0000_0010_1000_1101, 2),
            272: i2b(0b0000_0010_1000_1110, 2),
            }

try:
    for padding in paddings:
        padding_bytes, _ = padding_len_bytes(padding)
        print("\rPadding", padding, "was", padding_bytes, end="")
        assert paddings[padding] == padding_bytes
except AssertionError as ae:
    print()
    raise ae

print("\rSuccess - padding_len_bytes                              ")

# MsgV3 format

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

    print("\r{}/{} - gen_init_msg".format(i+1, passes), end="")

print("\rSuccess - gen_init_msg")

# dynamic message fragments

udp_payload = get_random_bytes(FRAG_PAYLOAD_SIZE)

f = FragmentGenerator(udp_payload)

fragment = f.get_data_fragment()

_, frag_byte, payload = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE)

assert b2i(frag_byte) & FragmentGenerator.LAST_FRAG_FLAG
assert b2i(frag_byte) == 0b0100_0000
assert payload[0:FRAG_PAYLOAD_SIZE] == udp_payload
assert len(fragment) == FRAG_PAYLOAD_SIZE + FRAG_ID_SIZE + FRAG_FLAG_SIZE

udp_payload = get_random_bytes(FRAG_PAYLOAD_SIZE - 1)

f = FragmentGenerator(udp_payload)

fragment = f.get_data_fragment()

_, frag_byte, _, payload = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE, 1)

assert b2i(frag_byte) & FragmentGenerator.LAST_FRAG_FLAG
assert b2i(frag_byte) & FragmentGenerator.PADDING_FLAG
assert b2i(frag_byte) == 0b1100_0000
assert payload[0:FRAG_PAYLOAD_SIZE - 1] == udp_payload
assert len(fragment) == FRAG_PAYLOAD_SIZE + FRAG_ID_SIZE + FRAG_FLAG_SIZE

udp_payload = get_random_bytes(1)

f = FragmentGenerator(udp_payload)

fragment = f.get_data_fragment()

_, frag_byte, _, payload = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE, 2)

assert b2i(frag_byte) & FragmentGenerator.LAST_FRAG_FLAG
assert b2i(frag_byte) & FragmentGenerator.PADDING_FLAG
assert b2i(frag_byte) == 0b1100_0000
assert payload[0:1] == udp_payload
assert len(fragment) == FRAG_PAYLOAD_SIZE + FRAG_ID_SIZE + FRAG_FLAG_SIZE


print("\rSuccess - get_data_fragment")



