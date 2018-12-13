#!/usr/bin/python3 -u
"""Contains the EntryPoint object, which connects clients with a mix chain, by
converting them into mix messages before sending."""
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from petlib.ec import EcPt, EcGroup

from LinkEncryption import LinkDecryptor, LinkEncryptor
from UDPChannel import ChannelEntry
from constants import IPV4_LEN, PORT_LEN, SYM_KEY_LEN, UDP_MTU
from util import b2i, read_cfg_values, cut, b2ip, parse_ip_port

OWN_ADDR_ARG = "own_ip:port"
MIX_ADDR_ARG = "mix_ip:port"
KEYFILE_ARG = "keyfile"


class EntryPoint:
    """The EntryPoint connects Clients with the mix chain. It takes regular
    packets with a custom header (dest. ip and port) and parses them into mix
    fragments. These fragments are send to an ExitPoint over the mix chain,
    where they are reassembled and then sent to the actual destination.
    Responses that come in over the mix chain are reassembled here as well and
    sent to the clients that are responded to."""

    def __init__(self, listen_addr, addr_to_mix):
        # where to listen on
        self.own_addr = listen_addr

        # where to send mix fragments to
        self.mix_addr = addr_to_mix

        # map of (src_ip:port, dest_ip:port) to channel id
        self.ips2id = dict()

        # list of the asymmetric mix ciphers to encrypt channel init messages
        self.pub_comps = []

        # the socket we listen for packet on
        self.socket = None

        self.link_decryptor = LinkDecryptor(bytes(SYM_KEY_LEN))
        self.link_encryptor = LinkEncryptor(bytes(SYM_KEY_LEN))

    def set_keys(self, public_keys):
        """Initializes a cipher for en- and decrypting using the given keys."""
        self.pub_comps = public_keys

    def handle_mix_response(self, response):
        """Takes a mix fragment and the channel id it came from. This
        represents a part of a response that was send back through the mix
        chain."""
        chan_id, msg_ctr, fragment, msg_type = self.link_decryptor.decrypt(response)

        channel = ChannelEntry.table[chan_id]

        channel.response(msg_type + msg_ctr + fragment)

        # send received responses to their respective recipients without
        # waiting
        for mix_msg in channel.get_completed_responses():
            print(self, "Data {}:{} - {} <- {}".format(*channel.src_addr, channel.chan_id, len(mix_msg.payload)))

            self.socket.sendto(mix_msg.payload, channel.src_addr)

    def handle_client_request(self, request, src_addr):
        """Takes a message and the source address it came from. The destination
        header is cut off, parsed and mapped to a channel. Then the payload is
        separated into mix fragments and sent out with the channel id in front.
        """
        dest_ip, dest_port, payload = cut(request, IPV4_LEN, PORT_LEN)

        dest_addr = (b2ip(dest_ip), b2i(dest_port))

        if (src_addr, dest_addr) not in self.ips2id:
            channel = self.make_new_channel(src_addr, dest_addr)
        else:
            try:
                channel_id = self.ips2id[src_addr, dest_addr]

                channel = ChannelEntry.table[channel_id]
            except KeyError:
                del self.ips2id[src_addr, dest_addr]
                channel = self.make_new_channel(src_addr, dest_addr)

        # add fragments to internal packet list
        channel.request(payload)

    def make_new_channel(self, src_addr, dest_addr):
        channel = ChannelEntry(src_addr, dest_addr, self.pub_comps)

        self.ips2id[(src_addr, dest_addr)] = channel.chan_id

        return channel

    def send_messages_to_mix(self):
        for channel in ChannelEntry.table.values():
            while channel.can_send():
                message = channel.get_message()
                cipher_text = self.link_encryptor.encrypt(message)

                print(self, "{}:{} - {} ->".format(*channel.src_addr, channel.chan_id), len(cipher_text))

                self.socket.sendto(cipher_text, mix_addr)

    def run(self):
        """Starts the EntryPoint main loop, listening on the given address and
        converting/relaying messages."""
        self.socket = socket(AF_INET, UDP)
        self.socket.bind(own_addr)

        print(self, "Listening on {}:{}.".format(*own_addr))
        while True:
            data, addr = self.socket.recvfrom(UDP_MTU)

            if addr == self.mix_addr:
                self.handle_mix_response(data)
            else:
                self.handle_client_request(data, addr)

            self.send_messages_to_mix()

    def __str__(self):
        return "EntryPoint"


if __name__ == "__main__":
    ap = ArgumentParser()

    ap.add_argument(
        OWN_ADDR_ARG, help="ip and port, to listen for packets on.")
    ap.add_argument("config", help="Config file describing the mix chain.")

    args = ap.parse_args()

    # get own ip and port
    own_addr = parse_ip_port(getattr(args, OWN_ADDR_ARG))

    mix_ip, mix_port, *mix_keys = read_cfg_values(args.config)

    # get mix ip and port
    mix_addr = parse_ip_port("{}:{}".format(mix_ip, mix_port))

    # this entry point instance
    entry_point = EntryPoint(own_addr, mix_addr)

    # prepare the keys
    public_keys = []

    group = EcGroup()

    for pub_file in mix_keys:
        with open("config/" + pub_file, "rb") as f:
            public_keys.append(EcPt.from_binary(f.read(), group))

    # init the ciphers
    entry_point.set_keys(public_keys)

    entry_point.run()
