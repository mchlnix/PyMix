#!/usr/bin/python3
"""The ExitPoint gets mix fragments from a mix and assembles them into complete
mix messages. Their payloads are sent to the destination from a fixed random
so that the destination can respond to it. Responses to that port get broken
up into fragments and sent back over the udp channel/mix chain."""
from argparse import ArgumentParser as ArgParser
from selectors import EVENT_READ
# standard library
from socket import socket, AF_INET, SOCK_DGRAM as UDP

# own
from UDPChannel import ChannelExit
from constants import UDP_MTU, CHAN_ID_SIZE
from util import parse_ip_port, cut, b2i


class ExitPoint:
    def __init__(self, own_addr):
        self.mix_addr = None

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
                    channel_id, payload = cut(packet, CHAN_ID_SIZE)
                    channel_id = b2i(channel_id)

                    # new channel detected
                    if channel_id not in ChannelExit.table.keys():
                        # automatically puts it into the channel table
                        # of ChannelExit
                        new_channel = ChannelExit(channel_id)

                        # first message of a channel is channel init
                        new_channel.parse_channel_init(payload)
                    else:
                        # request from an already established channel
                        ChannelExit.table[channel_id].recv_request(payload)

                # send responses to mix
                for packet in ChannelExit.to_mix:
                    self.sock_to_mix.send(packet)

                ChannelExit.to_mix.clear()


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
