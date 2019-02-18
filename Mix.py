#!/usr/bin/python3 -u
# standard library
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from petlib.bn import Bn

from LinkEncryption import LinkDecryptor, LinkEncryptor
from MsgV3 import get_pub_key
from UDPChannel import ChannelMid
from constants import UDP_MTU, SYM_KEY_LEN, DATA_MSG_FLAG
from util import read_cfg_values, shuffle

STORE_LIMIT = 1


class Mix:
    def __init__(self, secret, own_addr, next_addr, check_responses=True):
        # set up crypto
        # decrypt for messages from a client
        # encrypt for responses to the client
        self.priv_comp = secret
        self.pub_comp = get_pub_key(self.priv_comp)

        # create sockets
        # the 'port' arg is which one to listen and send datagrams from
        # the 'dest_ip:port' is the destination to send mix packets to
        # if we get packets from there, they are responses and need to be sent
        # to the address of the associated channel id
        self.incoming = socket(AF_INET, UDP)
        self.incoming.bind(own_addr)

        self.next_addr = next_addr
        self.mix_addr = None

        self.request_link_encryptor = LinkEncryptor(bytes(SYM_KEY_LEN))
        self.response_link_encryptor = LinkEncryptor(bytes(SYM_KEY_LEN))
        self.request_link_decryptor = LinkDecryptor(bytes(SYM_KEY_LEN))
        self.response_link_decryptor = LinkDecryptor(bytes(SYM_KEY_LEN))

        self.check_responses = check_responses

        print(self, "listening on {}:{}".format(*own_addr))

    def handle_mix_fragment(self, packet, addr):
        """Handles a message coming in from a client to be sent over the mix
        chain or from a mix earlier in the chain to its ultimate recipient. The
        given payload must be decrypted with the mixes symmetric key and the
        channel id must be changed from the incoming channel id given to it by
        the client or previous mix to an outgoing channel id mapped to it by
        this mix instance. The prepared packets are stored to be sent out
        later."""
        in_id, msg_ctr, fragment, msg_type = self.request_link_decryptor.decrypt(packet)

        lookup_key = (addr, in_id)

        # connect incoming chan id with address of the packet
        if msg_type == DATA_MSG_FLAG:
            # existing channel

            if lookup_key not in ChannelMid.table_in.keys():
                raise Exception("Got data msg for uninitialized channel", in_id)

            channel = ChannelMid.table_in[lookup_key]
            channel.forward_request(msg_ctr + fragment)
        else:
            # new channel
            if lookup_key in ChannelMid.table_in.keys():
                print(self, "Duplicate channel initialization for", in_id)
                channel = ChannelMid.table_in[lookup_key]
            else:
                channel = ChannelMid(in_id, addr, self.check_responses)

            channel.parse_channel_init(msg_ctr + fragment, self.priv_comp)

    def handle_response(self, response):
        """Handles a message, that came as a response to an initially made
        request. This means, that there should already be a channel established,
        since unsolicited messages through the mix network to a client are not
        expected nor supported. Expect a KeyError in that case."""
        # map the out going id, we gave the responder to the incoming id the
        # packet had, then get the src ip for that channel id
        out_id, msg_ctr, fragment, msg_type = self.response_link_decryptor.decrypt(response)

        channel = ChannelMid.table_out[out_id]

        channel.forward_response(msg_type + msg_ctr + fragment)

    def run(self):
        while True:
            # listen for packets
            packet, addr = self.incoming.recvfrom(UDP_MTU)

            # if the src addr of the last packet is the same as the addr of the
            # next hop, then this packet is a response, otherwise a mix fragment
            if addr == self.next_addr:
                self.handle_response(packet)
            else:
                self.handle_mix_fragment(packet, addr)

            # send out requests
            if len(ChannelMid.requests) >= STORE_LIMIT:
                # mix packets before sending
                shuffle(ChannelMid.requests)
                # send STORE_LIMIT packets
                for _ in range(STORE_LIMIT):
                    # use bound socket to send packets
                    packet = ChannelMid.requests.pop()

                    enc_packet = self.request_link_encryptor.encrypt(packet)

                    print(self, "Data/Init", "->", len(enc_packet))
                    self.incoming.sendto(enc_packet, self.next_addr)

            # send out responses
            if len(ChannelMid.responses) >= STORE_LIMIT:
                # mix packets before sending
                shuffle(ChannelMid.responses)
                # send STORE_LIMIT packets
                for _ in range(STORE_LIMIT):
                    address, packet = ChannelMid.responses.pop()

                    enc_packet = self.response_link_encryptor.encrypt(packet)

                    print(self, "Data/Init", "<-", address, len(enc_packet))
                    self.incoming.sendto(enc_packet, address)

    def __repr__(self):
        return "Mix:"


if __name__ == "__main__":
    ap = ArgumentParser(
        description="Very simple mix implementation in python.")
    ap.add_argument("config",
                    help="A file containing configurations for the mix.")

    args = ap.parse_args()

    # get configurations

    last_mix, listen_ip, listen_port, next_ip, next_port, secret_file = read_cfg_values(args.config)

    with open("config/" + secret_file, "rb") as f:
        secret = Bn.from_binary(f.read())

    listen_addr = (listen_ip, int(listen_port))

    next_hop_addr = (next_ip, int(next_port))

    mix = Mix(secret, listen_addr, next_hop_addr, last_mix != "true")

    mix.run()
