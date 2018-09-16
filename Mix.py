#!/usr/bin/python3 -u
# standard library
from random import randint
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from argparse import ArgumentParser
# third party
from Crypto.Cipher import AES
from Crypto.Random.random import StrongRandom
# own
from util import i2b, b2i, get_random_bytes
from MixMessage import FRAG_SIZE
from TwoWayTable import TwoWayTable

STORE_LIMIT = 1

CHAN_ID_SIZE = 2

MIN_CHAN_ID = 1
MAX_CHAN_ID = 2**(8*CHAN_ID_SIZE)-1

EXPLICIT_IV_SIZE = AES.block_size

PACKET_SIZE = CHAN_ID_SIZE + FRAG_SIZE + EXPLICIT_IV_SIZE


def decrypt_fragment(ciphers, fragment):
    for cipher in ciphers:
        fragment = cipher.decrypt(fragment)[EXPLICIT_IV_SIZE:]

    return fragment


def encrypt_fragment(ciphers, fragment):
    for cipher in ciphers:
        fragment = cipher.encrypt(get_random_bytes(EXPLICIT_IV_SIZE) +
                                  fragment)

    return fragment


def random_channel_id():
    return randint(MIN_CHAN_ID, MAX_CHAN_ID)


def get_chan_id(payload):
    """Reads the channel id of a given packet and returns it as an integer."""
    return b2i(payload[0:CHAN_ID_SIZE])


def get_payload(packet):
    return packet[CHAN_ID_SIZE:]


def get_outgoing_chan_id(in_chan_id):
    """Looks up the associated outgoing channel id of the given incoming
    channel id and returns it. If not found one will be generated."""
    if in_chan_id not in chan_table.in_channels:
        random_out_id = random_channel_id()
        while random_out_id in chan_table.out_channels:
            # if channel id is already taken
            random_out_id = random_channel_id()

        print("New connection:", in_chan_id, "->", random_out_id)
        chan_table.out_channel[in_chan_id] = random_out_id

    return chan_table.out_channel[in_chan_id]


def handle_mix_fragment(payload, source):
    """Handles a message coming in from a client to be sent over the mix chain
    or from a mix earlier in the chain to its ultimate recipient. The given
    payload must be decrypted with the mixes symmetric key and the channel id
    must be changed from the incoming channel id given to it by the client or
    previous mix to an outgoing channel id mapped to it by this mix instance.
    The prepared packets are stored to be sent out later."""
    # connect incoming chan id with address of the packet
    in_id = get_chan_id(payload)

    inchan2ip[in_id] = source

    # get or generate outgoing channel id for incoming channel id
    out_id = get_outgoing_chan_id(in_id)

    # decrypt payload and add new channel id
    plain = (i2b(out_id, CHAN_ID_SIZE) +
             decrypt_fragment([decryptor], payload[CHAN_ID_SIZE:]))

    print(in_id, "->", out_id, "Len:", len(plain))

    # store packet
    packet_store.append((plain, nexthop))


def handle_response(payload):
    """Handles a message, that came as a response to an initially made request.
    This means, that there should already be a channel established, since
    unsolicited messages through the mix network to a client are not expected
    nor supported. Expect a KeyError in that case."""
    # map the out going id, we gave the responder to the incoming id the packet
    # had, then get the src ip for that channel id
    out_id = get_chan_id(payload)
    in_id = chan_table.in_channel[out_id]
    dest = inchan2ip[in_id]

    # encrypt the payload and add the original channel id
    cipher_text = (i2b(in_id, CHAN_ID_SIZE) +
                   encrypt_fragment([encryptor], payload[CHAN_ID_SIZE:]))

    print(in_id, "<-", out_id, "Len:", len(cipher_text))

    # store the packet for sending
    packet_store.append((cipher_text, dest))

# pylint: disable=C0103
if __name__ == "__main__":
    ap = ArgumentParser(description="Very simple mix implementation in " +
                        "python.")
    ap.add_argument("position", help="the index of the mix in the chain, 1-n.")
    ap.add_argument("port", help="the port to listen for incoming packets.")
    ap.add_argument("dest_ip:port", help="ip address pair to send decrypted " +
                    "packets to. ex. 127.0.0.1:12345")
    ap.add_argument("keyfile", help="the file to read the key from.")
    ap.add_argument("-of", "--onefile", help="read the nth line from the" +
                    " keyfile as the key. n is the given position argument.",
                    action="store_true", default=False)

    args = ap.parse_args()

    # get key
    with open(args.keyfile, "r") as keyfile:
        if args.onefile:
            key = keyfile.readlines()[int(args.position)-1]
        else:
            key = keyfile.read()

    key = key.strip()

    # set up crypto
    # decrypt for messages from a client
    # encrypt for responses to the client
    encryptor = AES.new(key.encode("ascii"), AES.MODE_CBC)
    decryptor = AES.new(key.encode("ascii"), AES.MODE_CBC)

    # create sockets
    # the 'port' arg is which one to listen and send datagrams from
    # the 'dest_ip:port' is the destination to send mix packets to
    # if we get packets from there, they are responses and need to be sent
    # to the address of the associated channel id
    own_port = int(args.port)
    incoming = socket(AF_INET, UDP)
    incoming.bind(("127.0.0.1", own_port))

    ip, port = getattr(args, "dest_ip:port").split(":")
    nexthop = (ip, int(port))

    # stores packets ready to be sent and their destination in a batch
    packet_store = []

    print("Mix.py listening on Port {}".format(args.port))

    # channel table, which maps incoming channels to outgoing channels
    # and vice versa
    chan_table = TwoWayTable("in_channel", "out_channel")

    # table of channel ids mapped to the ip:port they came from. used for
    # responses, so they are sent to the right recipient
    inchan2ip = {}

    while True:
        # listen for packets
        packet, addr = incoming.recvfrom(10000)

        # if the src addr of the last packet is the same as the addr of the
        # next hop, then this packet is a response, otherwise a mix fragment
        if addr == nexthop:
            handle_response(packet)
        else:
            handle_mix_fragment(packet, addr)

        # when store full, or time is right reorder store
        if len(packet_store) >= STORE_LIMIT:
            # mix packets before sending
            StrongRandom().shuffle(packet_store)
            # flush store
            for packet, dest_addr in packet_store:
                # use bound socket to send packets
                incoming.sendto(packet, dest_addr)

            packet_store.clear()
