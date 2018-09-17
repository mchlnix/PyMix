#!/usr/bin/python3 -u
# standard library
from random import randint
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from argparse import ArgumentParser
# third party
from Crypto.Cipher import AES
from Crypto.Random.random import StrongRandom
# own
from util import i2b, b2i
from Ciphers.CBC_CS import default_cipher
from MixMessage import FRAG_SIZE
from TwoWayTable import TwoWayTable

STORE_LIMIT = 1

CHAN_ID_SIZE = 2

MIN_CHAN_ID = 1
MAX_CHAN_ID = 2**(8*CHAN_ID_SIZE)-1

EXPLICIT_IV_SIZE = AES.block_size

class Mix():
    def __init__(self, key, own_addr, next_addr):
        # set up crypto
        # decrypt for messages from a client
        # encrypt for responses to the client
        self.cipher = default_cipher([key])

        # create sockets
        # the 'port' arg is which one to listen and send datagrams from
        # the 'dest_ip:port' is the destination to send mix packets to
        # if we get packets from there, they are responses and need to be sent
        # to the address of the associated channel id
        self.incoming = socket(AF_INET, UDP)
        self.incoming.bind(own_addr)

        self.next_addr = next_addr

        # stores tuples of packets and their destination in a batch
        self.packet_store = []

        print("Mix.py listening on Port {}".format(args.port))

        # channel table, which maps incoming channels to outgoing channels
        # and vice versa
        self.chan_table = TwoWayTable("in_channel", "out_channel")

        # table of channel ids mapped to the ip:port they came from. used for
        # responses, so they are sent to the right recipient
        self.inchan2ip = {}

    def get_outgoing_chan_id(self, in_chan_id):
        """Looks up the associated outgoing channel id of the given incoming
        channel id and returns it. If not found one will be generated."""
        if in_chan_id not in self.chan_table.in_channels:
            random_out_id = random_channel_id()
            while random_out_id in self.chan_table.out_channels:
                # if channel id is already taken
                random_out_id = random_channel_id()

            print("New connection:", in_chan_id, "->", random_out_id)
            self.chan_table.out_channel[in_chan_id] = random_out_id

        return self.chan_table.out_channel[in_chan_id]

    def handle_mix_fragment(self, payload, source):
        """Handles a message coming in from a client to be sent over the mix chain
        or from a mix earlier in the chain to its ultimate recipient. The given
        payload must be decrypted with the mixes symmetric key and the channel id
        must be changed from the incoming channel id given to it by the client or
        previous mix to an outgoing channel id mapped to it by this mix instance.
        The prepared packets are stored to be sent out later."""
        # connect incoming chan id with address of the packet
        in_id = get_chan_id(payload)

        self.inchan2ip[in_id] = source

        # get or generate outgoing channel id for incoming channel id
        out_id = self.get_outgoing_chan_id(in_id)

        # decrypt payload and add new channel id
        plain = (i2b(out_id, CHAN_ID_SIZE) +
                 self.cipher.decrypt(payload[CHAN_ID_SIZE:]))

        print(in_id, "->", out_id, "Len:", len(plain))

        # store packet
        self.packet_store.append((plain, self.next_addr))

    def handle_response(self, payload):
        """Handles a message, that came as a response to an initially made request.
        This means, that there should already be a channel established, since
        unsolicited messages through the mix network to a client are not expected
        nor supported. Expect a KeyError in that case."""
        # map the out going id, we gave the responder to the incoming id the packet
        # had, then get the src ip for that channel id
        out_id = get_chan_id(payload)
        in_id = self.chan_table.in_channel[out_id]
        dest = self.inchan2ip[in_id]

        # encrypt the payload and add the original channel id
        cipher_text = (i2b(in_id, CHAN_ID_SIZE) +
                       self.cipher.encrypt(payload[CHAN_ID_SIZE:]))

        print(in_id, "<-", out_id, "Len:", len(cipher_text))

        # store the packet for sending
        self.packet_store.append((cipher_text, dest))

    def run(self):
        while True:
            # listen for packets
            packet, addr = self.incoming.recvfrom(10000)

            # if the src addr of the last packet is the same as the addr of the
            # next hop, then this packet is a response, otherwise a mix fragment
            if addr == self.next_addr:
                self.handle_response(packet)
            else:
                self.handle_mix_fragment(packet, addr)

            # when store full, or time is right reorder store
            if len(self.packet_store) >= STORE_LIMIT:
                # mix packets before sending
                StrongRandom().shuffle(self.packet_store)
                # flush store
                for packet, dest_addr in self.packet_store:
                    # use bound socket to send packets
                    self.incoming.sendto(packet, dest_addr)

                self.packet_store.clear()


def random_channel_id():
    return randint(MIN_CHAN_ID, MAX_CHAN_ID)


def get_chan_id(payload):
    """Reads the channel id of a given packet and returns it as an integer."""
    return b2i(payload[0:CHAN_ID_SIZE])


def get_payload(packet):
    return packet[CHAN_ID_SIZE:]


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

    own_port = int(args.port)
    own_addr = ("127.0.0.1", own_port)

    ip, port = getattr(args, "dest_ip:port").split(":")
    next_addr = (ip, int(port))

    mix = Mix(key, own_addr, next_addr)

    mix.run()
