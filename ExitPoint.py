#!/usr/bin/python3
"""The ExitPoint gets mix fragments from a mix and assembles them into complete
mix messages. Their payloads are sent to the destination from a fixed random
so that the destination can respond to it. Responses to that port get broken
up into fragments and sent back over the udp channel/mix chain."""
from argparse import ArgumentParser as ArgParser
from selectors import EVENT_READ
# standard library
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from LinkEncryption import LinkDecryptor, LinkEncryptor
from UDPChannel import ChannelExit
from constants import UDP_MTU, SYM_KEY_LEN, CHAN_INIT_MSG_FLAG, INIT_OVERHEAD
from util import parse_ip_port, cut


class ExitPoint:
    def __init__(self, own_addr):
        self.mix_addr = None

        # the socket the mix sends fragments to
        self.sock_to_mix = socket(AF_INET, UDP)
        self.sock_to_mix.bind(own_addr)
        self.sock_to_mix.setblocking(False)

        # add it to the socket selector in Channel Exit
        ChannelExit.sock_sel.register(self.sock_to_mix, EVENT_READ)

        self.link_decryptor = LinkDecryptor(bytes(SYM_KEY_LEN))
        self.link_encryptor = LinkEncryptor(bytes(SYM_KEY_LEN))

    def run(self):
        while True:
            events = ChannelExit.sock_sel.select()

            for key, _ in events:
                channel = key.data

                if channel is not None:
                    # if the socket is associated with a channel, it's a
                    # response
                    response = channel.out_sock.recv(UDP_MTU)

                    channel.recv_response(response)
                else:
                    # the only socket without a channel is the mix socket
                    sock = key.fileobj

                    # we assume the first received message will be from the mix
                    if self.mix_addr is None:
                        packet, self.mix_addr = sock.recvfrom(UDP_MTU)
                        sock.connect(self.mix_addr)
                    else:
                        packet = sock.recv(UDP_MTU)

                    chan_id, msg_ctr, fragment, msg_type = self.link_decryptor.decrypt(packet)

                    # new channel detected
                    if msg_type == CHAN_INIT_MSG_FLAG:
                        # automatically puts it into the channel table
                        # of ChannelExit
                        if chan_id in ChannelExit.table.keys():
                            print(self, "Received Channel Init message for established Channel", chan_id)

                            channel = ChannelExit.table[chan_id]

                            init_overhead, fragment = cut(fragment, INIT_OVERHEAD)

                            channel.recv_request(fragment)
                        else:
                            channel = ChannelExit(chan_id)

                            # first message of a channel is channel init
                            channel.parse_channel_init(fragment)

                        channel.send_chan_confirm()
                    else:
                        # data msg

                        if chan_id not in ChannelExit.table.keys():
                            raise Exception("Received Data Msg before Channel was established", chan_id)
                        else:
                            ChannelExit.table[chan_id].recv_request(msg_ctr + fragment)

                # send responses to mix
                for packet in ChannelExit.to_mix:
                    cipher_text = self.link_encryptor.encrypt(packet)

                    print(self, "Data/Init <-", len(cipher_text))
                    self.sock_to_mix.send(cipher_text)

                ChannelExit.to_mix.clear()

    def __str__(self):
        return "ExitPoint"


if __name__ == "__main__":
    parser = ArgParser(description="Receives data on the specified ip:port" +
                                   "using UDP and prints it on stdout.")
    parser.add_argument("ip:port", help="IP and Port pair to listen for " +
                                        "datagrams on")

    args = parser.parse_args()

    own_socket_addr = parse_ip_port(getattr(args, "ip:port"))
    print("Listening on {}:{}".format(*own_socket_addr))

    exit_point = ExitPoint(own_socket_addr)
    exit_point.run()
