#!/usr/bin/python3 -u
"""Contains the EntryPoint object, which connects clients with a mix chain, by
converting them into mix messages before sending."""
# standard library
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from argparse import ArgumentParser
# third party
from Crypto.Cipher import AES
# own
from Mix import PACKET_SIZE, random_channel_id, get_chan_id, get_payload
from util import items_from_file, i2b, b2i, i2ip
from util import parse_ip_port
from MixMessage import make_fragments, MixMessageStore
from TwoWayTable import TwoWayTable

UDP_MTU = 65535

OWN_ADDR_ARG = "own_ip:port"
MIX_ADDR_ARG = "mix_ip:port"
KEYFILE_ARG = "keyfile"


class EntryPoint():
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
        self.chan_table = TwoWayTable("addr_pair", "channel_id")

        # stores tuples of payload and destination to send out
        self.packets = []

        # list of the ciphers to apply to mix messages in correct order
        self.ciphers = []

        # the socket we listen for packet on
        self.socket = None

    def set_cipher_chain(self, cipher_list):
        """Saves the given list of ciphers to be applied to incoming mix
        messages and in reverse order to outgoing mix messages."""
        self.ciphers = cipher_list

    def get_outgoing_chan_id(self, src_addr, dest_addr):
        """Get the channel id for a src and dest address pair, or generate one, if
        the channel is new."""
        addr_pair = (src_addr, dest_addr)
        if addr_pair not in self.chan_table.addr_pairs:
            random_id = random_channel_id()
            while random_id in self.chan_table.channel_ids:
                random_id = random_channel_id()

            self.chan_table.channel_id[addr_pair] = random_id
            print("New channel", random_id, "for", src_addr, "to", dest_addr)

        return self.chan_table.channel_id[addr_pair]

    def add_packets_from_mix_message(self, message, dest, chan_id):
        """Takes a payload and a channel id and turns it into mix fragments ready
           to be sent out."""
        for frag in make_fragments(message, dest):
            packet = frag
            for cipher in self.ciphers:
                packet = cipher.encrypt(packet)

            self.packets.append(i2b(chan_id, 2) + packet)

    def handle_mix_fragment(self, response):
        """Takes a mix fragment and the channel id it came from. This represents a
        part of a response that was send back through the mix chain."""
        channel_id = get_chan_id(response)
        fragment = get_payload(response)

        print(len(fragment), "b: client <-", channel_id, "mix")

        for cipher in reversed(self.ciphers):
            fragment = cipher.decrypt(fragment)

        mix_msg = self.mix_msg_store.parse_fragment(fragment)

        # send received responses to their respective recipients
        for mix_msg in self.mix_msg_store.completed():
            dest_addr, _ = self.chan_table.addr_pair[channel_id]

            print("Sending", len(mix_msg.payload), "bytes to", dest_addr)
            self.socket.sendto(mix_msg.payload, dest_addr)

        self.mix_msg_store.remove_completed()

    def handle_request(self, request, src_addr):
        """Takes a message and the source address it came from. The destination
        header is cut off, parsed and mapped to a channel. Then the payload is
        separated into mix fragments and sent out with the channel id in front.
        """
        dest_ip, dest_port = b2i(request[0:4]), b2i(request[4:6])
        dest_ip = i2ip(dest_ip)

        dest_addr = (dest_ip, dest_port)

        chan_id = self.get_outgoing_chan_id(src_addr, dest_addr)
        self.chan_table.addr_pair[chan_id] = (src_addr, dest_addr)

        print(len(request)-6, "b:", src_addr, chan_id, "-> mix")

        self.add_packets_from_mix_message(request[6:], dest_addr, chan_id)

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
                assert len(data) == PACKET_SIZE
                self.handle_mix_fragment(data)
            else:
                # got a request to send through the mixes
                self.handle_request(data, addr)

            for packet in self.packets:
                self.socket.sendto(packet, mix_addr)

            self.packets.clear()

if __name__ == "__main__":
    ap = ArgumentParser()

    ap.add_argument(OWN_ADDR_ARG, help="ip and port, to listen for packets" +
                    "on.")
    ap.add_argument(MIX_ADDR_ARG, help="ip and port of the mix.")
    ap.add_argument(KEYFILE_ARG, help="file with keys to encrypt the " +
                    "payloads with. Will be read line by line. Keys are " +
                    "used in reversed order.")

    args = ap.parse_args()

    # get own ip and port
    own_addr = parse_ip_port(getattr(args, OWN_ADDR_ARG))

    # get mix ip and port
    mix_addr = parse_ip_port(getattr(args, MIX_ADDR_ARG))

    # this entry point instance
    entry_point = EntryPoint(own_addr, mix_addr)

    # read in the keys
    keyfile = getattr(args, KEYFILE_ARG)
    keys = items_from_file(keyfile)

    # init the ciphers
    ciphers = []

    for key in reversed(keys):
        ciphers.append(AES.new(key.encode("ascii"), AES.MODE_ECB))

    entry_point.set_cipher_chain(ciphers)

    entry_point.run()
