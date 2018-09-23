#!/usr/bin/python3 -u
"""Contains the EntryPoint object, which connects clients with a mix chain, by
converting them into mix messages before sending."""
from argparse import ArgumentParser
# standard library
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from Ciphers.CBC_CS import default_cipher
from MixMessage import MixMessageStore
# own
from UDPChannel import ChannelEntry
from util import b2i, i2ip, read_cfg_values
from util import parse_ip_port, get_chan_id, get_payload

UDP_MTU = 65535

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

        # stores mix fragments and puts them together into mix messages
        self.mix_msg_store = MixMessageStore()

        # map of (src_ip:port, dest_ip:port) to channel id
        self.ips2id = dict()

        # stores tuples of payload and destination to send out
        self.packets = []

        # list of the ciphers to apply to mix messages in correct order
        self.cipher = None

        # the socket we listen for packet on
        self.socket = None

    def set_keys(self, mix_keys):
        """Initializes a cipher for en- and decrypting using the given keys."""
        self.cipher = default_cipher(mix_keys)

    def handle_mix_fragment(self, response):
        """Takes a mix fragment and the channel id it came from. This represents a
        part of a response that was send back through the mix chain."""
        channel_id = get_chan_id(response)
        fragment = get_payload(response)

        channel = ChannelEntry.id2channel[channel_id]

        channel.recv_response_fragment(fragment)

        # send received responses to their respective recipients without waiting
        for mix_msg in channel.get_completed_responses():
            self.socket.sendto(mix_msg.payload, channel.src_addr)

    def handle_request(self, request, src_addr):
        """Takes a message and the source address it came from. The destination
        header is cut off, parsed and mapped to a channel. Then the payload is
        separated into mix fragments and sent out with the channel id in front.
        """
        dest_ip, dest_port = b2i(request[0:4]), b2i(request[4:6])
        dest_ip = i2ip(dest_ip)

        dest_addr = (dest_ip, dest_port)

        if (src_addr, dest_addr) not in self.ips2id:
            # new channel needs to be opened
            channel = ChannelEntry(src_addr, dest_addr, 3)
            self.ips2id[(src_addr, dest_addr)] = channel.chan_id

            init_msg = channel.chan_init_msg(self.cipher)
            ChannelEntry.to_mix.append(init_msg)  # TODO better way
        else:
            channel = ChannelEntry.id2channel[self.ips2id[src_addr, dest_addr]]

        # add fragments to internal packet list
        channel.make_request_fragments(request[6:])

    def run(self):
        """Starts the EntryPoint main loop, listening on the given address and
        converting/relaying messages."""
        self.socket = socket(AF_INET, UDP)
        self.socket.bind(own_addr)

        print("Listening on {}:{}.".format(*own_addr))
        while True:
            data, addr = self.socket.recvfrom(UDP_MTU)

            if addr == self.mix_addr:
                # Got a response through the mixes
                self.handle_mix_fragment(data)
            else:
                # got a request to send through the mixes
                self.handle_request(data, addr)

            # send to mix
            for packet in ChannelEntry.to_mix:
                self.socket.sendto(packet, mix_addr)

            ChannelEntry.to_mix.clear()


if __name__ == "__main__":
    ap = ArgumentParser()

    ap.add_argument(OWN_ADDR_ARG, help="ip and port, to listen for packets" +
                    "on.")
    ap.add_argument("config", help="Config file describing the mix chain.")

    args = ap.parse_args()

    # get own ip and port
    own_addr = parse_ip_port(getattr(args, OWN_ADDR_ARG))

    mix_ip, mix_port, *mix_keys = read_cfg_values(args.config)

    # get mix ip and port
    mix_addr = parse_ip_port("{}:{}".format(mix_ip, mix_port))

    # this entry point instance
    entry_point = EntryPoint(own_addr, mix_addr)

    # preparethe keys
    keys = [key.encode("ascii") for key in mix_keys]

    # init the ciphers
    entry_point.set_keys(keys)

    entry_point.run()
