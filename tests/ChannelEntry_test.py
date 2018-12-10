from MixMessage import INIT_PACKET_SIZE, FragmentGenerator
from MsgV3 import get_pub_key, gen_priv_key
from ReplayDetection import ReplayDetectedError
from UDPChannel import ChannelEntry
from constants import MIX_COUNT, CHAN_ID_SIZE, FLAG_LEN, CTR_PREFIX_LEN
from util import gen_sym_key, ctr_cipher, i2b

src_addr = ("127.0.0.1", 12345)
dest_addr = ("127.0.0.2", 23456)

private_keys = [gen_priv_key() for i in range(MIX_COUNT)]
public_keys = [get_pub_key(private_key) for private_key in private_keys]


def test_chan_init_msg():
    channel = ChannelEntry(src_addr, dest_addr, public_keys)

    channel_initialization_message = channel.chan_init_msg()

    assert len(channel_initialization_message) == CHAN_ID_SIZE + FLAG_LEN + CTR_PREFIX_LEN + INIT_PACKET_SIZE


def test_replay_detection():
    channel = ChannelEntry(src_addr, dest_addr, public_keys)

    counter = 1234
    sym_key = gen_sym_key()
    channel.sym_keys = [sym_key] * MIX_COUNT

    print("Counter: {}".format(counter))

    packet = FragmentGenerator(bytes(100)).get_data_fragment()

    for _ in range(MIX_COUNT):
        cipher = ctr_cipher(sym_key, counter)

        packet = i2b(counter, CTR_PREFIX_LEN) + cipher.encrypt(packet)

    channel.recv_response_fragment(packet)

    try:
        channel.recv_response_fragment(packet)
        assert False
    except ReplayDetectedError:
        assert True

    counter += 1

    for _ in range(MIX_COUNT):
        cipher = ctr_cipher(sym_key, counter)

        packet = i2b(counter, CTR_PREFIX_LEN) + cipher.encrypt(packet)

    channel.recv_response_fragment(packet)
