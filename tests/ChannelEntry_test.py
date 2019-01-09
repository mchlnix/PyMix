import pytest

from MixMessage import INIT_PACKET_SIZE, FragmentGenerator
from MsgV3 import get_pub_key, gen_priv_key
from ReplayDetection import ReplayDetectedError
from UDPChannel import ChannelEntry
from constants import MIX_COUNT, CHAN_ID_SIZE, MSG_TYPE_FLAG_LEN, CTR_PREFIX_LEN
from util import gen_sym_key, ctr_cipher, i2b, cut, b2i

src_addr = ("127.0.0.1", 12345)
dest_addr = ("127.0.0.2", 23456)

private_keys = [gen_priv_key() for i in range(MIX_COUNT)]
public_keys = [get_pub_key(private_key) for private_key in private_keys]


def test_get_init_message():
    channel = ChannelEntry(src_addr, dest_addr, public_keys)

    channel_initialization_message = channel._get_init_message()

    assert len(channel_initialization_message) == CHAN_ID_SIZE + MSG_TYPE_FLAG_LEN + CTR_PREFIX_LEN + INIT_PACKET_SIZE


def test_replay_detection():
    channel = ChannelEntry(src_addr, dest_addr, public_keys)

    counter = 1234
    sym_key = gen_sym_key()
    channel.req_sym_keys = [sym_key] * MIX_COUNT

    print("Counter: {}".format(counter))

    packet = FragmentGenerator(bytes(100)).get_data_fragment()

    packet = channel._encrypt_fragment(packet)

    channel._receive_response_fragment(packet)

    try:
        channel._receive_response_fragment(packet)
        assert False
    except ReplayDetectedError:
        assert True

    packet = channel._encrypt_fragment(packet)

    channel._receive_response_fragment(packet)


def test_encrypt_fragment():
    channel = ChannelEntry(src_addr, dest_addr, public_keys)

    sym_key = gen_sym_key()
    channel.req_sym_keys = [sym_key] * MIX_COUNT

    fragment = FragmentGenerator(bytes(100)).get_data_fragment()

    packet1 = channel._encrypt_fragment(fragment)

    packet2 = fragment
    counter = 1

    for _ in range(MIX_COUNT):
        cipher = ctr_cipher(sym_key, counter)

        packet2 = i2b(counter, CTR_PREFIX_LEN) + cipher.encrypt(packet2)

    assert packet1 == packet2


@pytest.mark.skip(reason="no way of currently testing this")
def test_decrypt_fragment():
    channel = ChannelEntry(src_addr, dest_addr, public_keys)

    sym_key = gen_sym_key()
    channel.req_sym_keys = [sym_key] * MIX_COUNT

    fragment = FragmentGenerator(bytes(100)).get_data_fragment()

    fragment = channel._encrypt_fragment(fragment)

    packet1 = channel._decrypt_fragment(fragment)

    for _ in range(MIX_COUNT):
        msg_ctr, fragment = cut(fragment, CTR_PREFIX_LEN)

        cipher = ctr_cipher(sym_key, b2i(msg_ctr))

        fragment = cipher.decrypt(fragment)

    packet2 = fragment

    assert packet1 == packet2
