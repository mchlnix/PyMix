#!/usr/bin/python3 -u
# standard library
from argparse import ArgumentParser
# third party
from Crypto.Cipher import AES
# own
from Mix import PACKET_SIZE, random_channel_id, get_chan_id, get_packet
from util import items_from_file, i2b, b2i, i2ip
from util import parse_ip_port
from Receiver import get_udp as get_udp_receiver
from MixMessage import make_fragments, MixMessageStore
from TwoWayTable import TwoWayTable

UDP_MTU = 65535

OWN_ADDR_ARG = "own_ip:port"
MIX_ADDR_ARG = "mix_ip:port"
KEYFILE_ARG = "keyfile"

def get_outgoing_chan_id(src_addr, dest_addr):
    addr_pair = (src_addr, dest_addr)
    if addr_pair not in chan_table.addr_pairs:
        random_id = random_channel_id()
        while random_id in chan_table.channel_ids:
            random_id = random_channel_id()

        chan_table.channel_id[addr_pair] = random_id
        print("New channel", random_id, "for", src_addr, "to", dest_addr)

    return chan_table.channel_id[addr_pair]

def packets_from_mix_message(message, dest, channel_id):
    """Takes a payload and a channel id and turns it into mix fragments ready
       to be sent out."""
    _packets = []
    for frag in make_fragments(message, *dest):
        packet = frag
        for cipher in ciphers:
            packet = cipher.encrypt(packet)

        _packets.append(i2b(channel_id, 2) + packet)

    return _packets

def handle_mix_fragment(chan_id, fragment):
    print(len(fragment), "b: client <-", chan_id, "mix")
    for cipher in reversed(ciphers):
        fragment = cipher.decrypt(fragment)

    mix_msg = store.parse_fragment(fragment)

    # send received responses to their respective recipients
    for mix_msg in store.completed():
        dest_addr, _ = chan_table.addr_pair[chan_id]

        print("Sending", len(mix_msg.payload), "bytes to", dest_addr)
        r.sendto(mix_msg.payload, dest_addr)

    store.remove_completed()

def handle_request(request, src_addr):
    dest_ip, dest_port = b2i(request[0:4]), b2i(request[4:6])
    dest_ip = i2ip(dest_ip)

    dest_addr = (dest_ip, dest_port)

    chan_id = get_outgoing_chan_id(src_addr, dest_addr)
    chan_table.addr_pair[chan_id] = (src_addr, dest_addr)

    print(len(request)-6, "b:", r.getaddr(), chan_id, "-> mix")

    packets.extend(packets_from_mix_message(request[6:], dest_addr, chan_id))

# pylint: disable=C0103
if __name__ == "__main__":
    ap = ArgumentParser()

    ap.add_argument(OWN_ADDR_ARG, help="ip and port, to listen for packets on.")
    ap.add_argument(MIX_ADDR_ARG, help="ip and port of the mix.")
    ap.add_argument(KEYFILE_ARG, help="file with keys to encrypt the " +
                    "payloads with. Will be read line by line. Keys are " +
                    "used in reversed order.")

    args = ap.parse_args()

    # read in the keys
    keyfile = getattr(args, KEYFILE_ARG)
    keys = items_from_file(keyfile)

    # init the ciphers
    ciphers = []

    for key in reversed(keys):
        ciphers.append(AES.new(key.encode("ascii"), AES.MODE_ECB))

    # map of (src_ip:port, dest_ip:port) to channel id
    chan_table = TwoWayTable("addr_pair", "channel_id")

    # stores mix fragments and puts them together into mix messages
    store = MixMessageStore()

    # stores tuples of payload and destination to send out
    packets = []

    # get mix ip and port
    mix_addr = parse_ip_port(getattr(args, MIX_ADDR_ARG))

    # get own ip and port
    own_addr = parse_ip_port(getattr(args, OWN_ADDR_ARG))

    # connect to first mix
    with get_udp_receiver(own_addr) as r:
        print("Listening on {}:{}.".format(*own_addr))
        while True:
            data = r.recv(UDP_MTU)

            if r.getaddr() == mix_addr:
                # Got a response through the mixes
                assert len(data) == PACKET_SIZE
                channel_id = get_chan_id(data)
                payload = get_packet(data)
                handle_mix_fragment(channel_id, payload)
            else:
                # got a request to send through the mixes
                handle_request(data, r.getaddr())

            for packet in packets:
                r.sendto(packet, mix_addr)

            packets.clear()
