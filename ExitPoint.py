#!/usr/bin/python3
"""The ExitPoint gets mix fragments from a mix and assembles them into complete
mix messages. Their payloads are sent to the destination from a fixed random
so that the destination can respond to it. Responses to that port get broken
up into fragments and sent back over the udp channel/mix chain."""
from argparse import ArgumentParser as ArgParser
from selectors import DefaultSelector, EVENT_READ
# standard library
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from MixMessage import MixMessageStore
from TwoWayTable import TwoWayTable
from UDPChannel import ChannelExit
# own
from constants import UDP_MTU
from util import parse_ip_port, get_chan_id, get_payload

# pylint: disable=E1101


class ExitPoint:
    def __init__(self, own_addr):
        self.mix_addr = None

        # a special container, which accepts mix fragments and reassembles them to
        # MixMessage objects. completed MixMessages can be queried and removed,
        # their payload is the original unencrypted payload
        self.store = MixMessageStore()

        # look up table to map sockets to destinations
        self.chan_table = TwoWayTable("channel_id", "channel")

        # remember how much padding a plain text has to have (see Cipher/CBC_CS.py)
        # channel id -> number of padding bytes
        self.padding_dict = {}

        # list of ports, that are listening for responses
        self.ports = []

        # returns the sockets with data in them, without blocking
        self.sock_sel = DefaultSelector()

        # the socket the mix sends fragments to
        self.sock_to_mix = socket(AF_INET, UDP)
        self.sock_to_mix.bind(own_addr)
        self.sock_to_mix.setblocking(False)

        ChannelExit.sock_sel.register(self.sock_to_mix, EVENT_READ)

    def run(self):
        while True:
            events = ChannelExit.sock_sel.select()

            for key, _ in events:
                channel = key.data

                if channel is not None:
                    # if the socket is associated with a channel, it's a
                    # response
                    channel.recv_response()
                else:
                    # the only socket without a channel is the mix socket
                    sock = key.fileobj

                    # we assume the first message we receive will be from the mix
                    if self.mix_addr is None:
                        packet, self.mix_addr = sock.recvfrom(UDP_MTU)
                        sock.connect(self.mix_addr)
                    else:
                        packet = sock.recv(UDP_MTU)

                    # parse packet
                    channel_id = get_chan_id(packet)
                    payload = get_payload(packet)

                    # new channel detected
                    if channel_id not in self.chan_table.channel_ids:
                        new_channel = ChannelExit(channel_id)

                        # first message of a channel is channel init
                        new_channel.parse_channel_init(payload)

                        self.chan_table.channel[channel_id] = new_channel
                    else:
                        # request from an already established channel
                        self.chan_table.channel[channel_id].recv_request(payload)

                # send responses to mix
                for packet in ChannelExit.to_mix:
                    self.sock_to_mix.send(packet)

                ChannelExit.to_mix.clear()


# pylint: disable=C0103
if __name__ == "__main__":
    parser = ArgParser(description="Receives data on the specified ip:port using " +
                       "UDP and prints it on stdout.")
    parser.add_argument("ip:port", help="IP and Port pair to listen for " +
                        "datagrams on")

    args = parser.parse_args()

    own_socket_addr = parse_ip_port(getattr(args, "ip:port"))
    print("Listening on {}:{}".format(*own_socket_addr))

    exit_point = ExitPoint(own_socket_addr)
    exit_point.run()
