#!/usr/bin/python3 -u
# standard library
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from petlib.bn import Bn

from LinkEncryption import LinkDecryptor, LinkEncryptor
from MsgV3 import get_pub_key
from UDPChannel import ChannelLastMix
from constants import UDP_MTU, SYM_KEY_LEN, DATA_MSG_FLAG, CHAN_ID_SIZE, MSG_TYPE_FLAG_LEN
from util import read_cfg_values, shuffle, cut

STORE_LIMIT = 1


class LastMix:
    def __init__(self, secret, own_addr, next_addr):
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

        self.response_link_encryptor = LinkEncryptor(bytes(SYM_KEY_LEN))
        self.request_link_decryptor = LinkDecryptor(bytes(SYM_KEY_LEN))

        print(self, "listening on {}:{}".format(*own_addr))

    def handle_mix_fragment(self, packet):
        in_id, msg_ctr, fragment, msg_type = self.request_link_decryptor.decrypt(packet)

        # connect incoming chan id with address of the packet
        if msg_type == DATA_MSG_FLAG:
            # existing channel

            if in_id not in ChannelLastMix.table.keys():
                raise Exception("Got data msg for uninitialized channel", in_id)

            channel = ChannelLastMix.table[in_id]
            channel.forward_request(msg_ctr + fragment)
        else:
            # new channel
            if in_id in ChannelLastMix.table.keys():
                print(self, "Duplicate channel initialization for", in_id)
                channel = ChannelLastMix.table[in_id]
            else:
                channel = ChannelLastMix(in_id, next_hop_addr)

            channel.parse_channel_init(msg_ctr + fragment, self.priv_comp)
            channel.send_chan_confirm()

    def handle_response(self, response):
        # encrypt the incoming message
        # disregard the message counter afterwards
        # break up the payload into fragments
        # put fragment messages into a list
        # send out if list is full

        out_id, msg_type, response = cut(CHAN_ID_SIZE, MSG_TYPE_FLAG_LEN, response)

        channel = ChannelLastMix.table[out_id]

        channel.response(msg_type, response)

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

            # send out responses
            if len(ChannelLastMix.responses) >= STORE_LIMIT:
                # mix packets before sending
                shuffle(ChannelLastMix.responses)
                # send STORE_LIMIT packets
                for _ in range(STORE_LIMIT):
                    packet = ChannelLastMix.responses.pop()

                    print(self, "Data/Init", "<-", len(packet))
                    self.incoming.sendto(self.response_link_encryptor.encrypt(packet), self.mix_addr)

    def __repr__(self):
        return "Mix:"


if __name__ == "__main__":
    ap = ArgumentParser(description="Very simple mix implementation in python.")
    ap.add_argument("config", help="A file containing configurations for the mix.")

    args = ap.parse_args()

    # get configurations

    last_mix, listen_ip, listen_port, next_ip, next_port, secret_file = read_cfg_values(args.config)

    with open("config/" + secret_file, "rb") as f:
        secret = Bn.from_binary(f.read())

    listen_addr = (listen_ip, int(listen_port))

    next_hop_addr = (next_ip, int(next_port))

    mix = LastMix(secret, listen_addr, next_hop_addr)

    mix.run()