#!/usr/bin/python3 -u
# standard library
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from Crypto.Cipher import AES
from Crypto.Random.random import StrongRandom

from Ciphers.CBC_CS import default_cipher
from UDPChannel import ChannelMid
from constants import CHAN_ID_SIZE, UDP_MTU
from util import get_chan_id

STORE_LIMIT = 1

EXPLICIT_IV_SIZE = AES.block_size


class Mix:
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
        self.mix_addr = None

        print("Mix.py listening on Port {}".format(args.port))

    def handle_mix_fragment(self, payload):
        """Handles a message coming in from a client to be sent over the mix chain
        or from a mix earlier in the chain to its ultimate recipient. The given
        payload must be decrypted with the mixes symmetric key and the channel id
        must be changed from the incoming channel id given to it by the client or
        previous mix to an outgoing channel id mapped to it by this mix instance.
        The prepared packets are stored to be sent out later."""
        # connect incoming chan id with address of the packet
        in_id = get_chan_id(payload)

        if in_id in ChannelMid.in2chan.keys():
            # existing channel
            channel = ChannelMid.in2chan[in_id]
            channel.forward_request(payload[CHAN_ID_SIZE:])
        else:
            # new channel
            channel = ChannelMid(in_id)

            plain = self.cipher.decrypt(payload[CHAN_ID_SIZE:])
            channel.parse_channel_init(plain)

    def handle_response(self, payload):
        """Handles a message, that came as a response to an initially made request.
        This means, that there should already be a channel established, since
        unsolicited messages through the mix network to a client are not expected
        nor supported. Expect a KeyError in that case."""
        # map the out going id, we gave the responder to the incoming id the packet
        # had, then get the src ip for that channel id
        out_id = get_chan_id(payload)

        channel = ChannelMid.out2chan[out_id]

        channel.forward_response(payload[CHAN_ID_SIZE:])

    def run(self):
        while True:
            # listen for packets
            packet, addr = self.incoming.recvfrom(UDP_MTU)

            # if the src addr of the last packet is the same as the addr of the
            # next hop, then this packet is a response, otherwise a mix fragment
            if addr == self.next_addr:
                self.handle_response(packet)
            else:
                if self.mix_addr is None:
                    self.mix_addr = addr
                self.handle_mix_fragment(packet)

            # send out requests
            if len(ChannelMid.requests) >= STORE_LIMIT:
                # mix packets before sending
                StrongRandom().shuffle(ChannelMid.requests)
                # send STORE_LIMIT packets
                for _ in range(STORE_LIMIT):
                    # use bound socket to send packets
                    packet = ChannelMid.requests.pop()
                    self.incoming.sendto(packet, self.next_addr)

            # send out responses
            if len(ChannelMid.responses) >= STORE_LIMIT:
                # mix packets before sending
                StrongRandom().shuffle(ChannelMid.responses)
                # send STORE_LIMIT packets
                for _ in range(STORE_LIMIT):
                    # use bound socket to send packets
                    packet = ChannelMid.responses.pop()
                    self.incoming.sendto(packet, self.mix_addr)


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
            mix_key = keyfile.readlines()[int(args.position)-1]
        else:
            mix_key = keyfile.read()

    mix_key = mix_key.strip().encode("ascii")

    own_port = int(args.port)
    listen_addr = ("127.0.0.1", own_port)

    ip, port = getattr(args, "dest_ip:port").split(":")
    next_hop_addr = (ip, int(port))

    mix = Mix(mix_key, listen_addr, next_hop_addr)

    mix.run()
