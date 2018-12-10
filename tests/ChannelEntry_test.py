from MixMessage import INIT_PACKET_SIZE
from MsgV3 import get_pub_key, gen_priv_key
from UDPChannel import ChannelEntry
from constants import MIX_COUNT, CHAN_ID_SIZE, FLAG_LEN, CTR_PREFIX_LEN

src_addr = ("127.0.0.1", 12345)
dest_addr = ("127.0.0.2", 23456)

private_keys = [gen_priv_key() for i in range(MIX_COUNT)]
public_keys = [get_pub_key(private_key) for private_key in private_keys]


def test_chan_init_msg():
    channel = ChannelEntry(src_addr, dest_addr, public_keys)

    channel_initialization_message = channel.chan_init_msg()

    assert len(channel_initialization_message) == CHAN_ID_SIZE + FLAG_LEN + CTR_PREFIX_LEN + INIT_PACKET_SIZE



