#!/usr/bin/python3
"""The ExitPoint gets mix fragments from a mix and assembles them into complete
mix messages. Their payloads are sent to the destination from a fixed random
so that the destination can respond to it. Responses to that port get broken
up into fragments and sent back over the udp channel/mix chain."""
# standard library
from random import randint
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from argparse import ArgumentParser as AP
from selectors import DefaultSelector, EVENT_READ
# own
from Mix import CHAN_ID_SIZE, FRAG_SIZE, get_chan_id, get_payload
from util import i2b, padded
from util import parse_ip_port
from MixMessage import MixMessageStore, make_fragments
from TwoWayTable import TwoWayTable

# pylint: disable=E1101

UDP_MTU = 65535

MIN_PORT = 50000
MAX_PORT = 60000


class ExitPoint:
    def __init__(self, own_addr):
        self.mix_addr = None

        # a special container, which accepts mix fragments and reassembles them to
        # MixMessage objects. completed MixMessages can be queried and removed,
        # their payload is the original unencrypted payload
        self.store = MixMessageStore()

        # look up table to map sockets to destinations
        self.sock_table = TwoWayTable("socket", "channel_id")

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

        self.sock_sel.register(self.sock_to_mix, EVENT_READ)

    def random_socket(self):
        """Returns a socket bound to a random port, that is not in use already."""

        while True:
            port = randint(MIN_PORT, MAX_PORT)

            if port in self.ports:
                # Port already in use by us
                continue

            try:
                new_sock = socket(AF_INET, UDP)
                new_sock.bind(("127.0.0.1", port))
                new_sock.setblocking(False)

                return new_sock
            except OSError:
                # Port already in use by another application, try a new one
                pass


    def handle_mix_fragment(self, packet):
        """The mix fragment gets added to the fragment store. If the channel id is
           not already known a socket will be created for the destination of the
           mix fragment and added to the socket table.
           If the fragment completes the mix message, all completed mix messages
           will be sent out over their sockets."""

        chan_id = get_chan_id(packet)
        fragment = get_payload(packet)

        # the plain text might still have random bytes at the end
        self.padding_dict[chan_id] = len(fragment) - FRAG_SIZE
        if len(fragment) < FRAG_SIZE:
            print(fragment)
        print("Plaintext had", self.padding_dict[chan_id], "bytes padding.")
        fragment = fragment[0:FRAG_SIZE]

        # add fragment to the mix message store
        parsed_frag = self.store.parse_fragment(fragment)

        # is this the first fragment from this channel?
        if chan_id not in self.sock_table.channel_ids:
            # a new udp channel was opened, save mapping and create socket
            self.sock_table.socket[chan_id] = self.random_socket()

            # make sure we only listen to the (eventual) destination of the mix
            # message
            self.sock_table.socket[chan_id].connect(parsed_frag.dest)

            # register socket to the socket selector
            self.sock_sel.register(self.sock_table.socket[chan_id], EVENT_READ)

        # send out the payload of completed MixMessages
        for mix_message in self.store.completed():
            # get the socket associated with the channel
            sock = self.sock_table.socket[chan_id]

            # make sure the destination is the same
            if mix_message.dest != sock.getpeername():
                raise Exception("The socket is connected to a different " +
                                "destination, than the mix message is targeting.")

            print(chan_id, "->", mix_message.dest)

            # send complete mix message to the destination
            sock.send(mix_message.payload)

        # remove sent messages
        self.store.remove_completed()


    def handle_response(self, sock):
        """Turns the response into a MixMessage and sends its fragments to the mix.
        """
        # get response data to set socket.getaddr()
        response = sock.recv(UDP_MTU)

        # get channel id associated with the socket the data came in from
        chan_id = self.sock_table.channel_id[sock]

        print(chan_id, "<-", sock.getpeername())

        if self.mix_addr is None:
            raise Exception("The mix address is not yet known, but there is " +
                            "already a response for it. Invalid State.")

        # we don't know the actual ip:port of the recipient. the EntryPoint will
        # get the response through the channel id and will know where to send it
        mix_frags = make_fragments(response, ("0.0.0.0", 0))

        # append channel id to the fragments
        for frag in mix_frags:
            self.sock_to_mix.send(i2b(chan_id, CHAN_ID_SIZE) +
                                  padded(frag, FRAG_SIZE + self.padding_dict[chan_id]))

    def run(self):
        while True:
            events = self.sock_sel.select()

            for key, _ in events:
                sock = key.fileobj

                # we assume the first message we receive will be from the mix
                if self.mix_addr is None:
                    packet, self.mix_addr = sock.recvfrom(UDP_MTU)
                    sock.connect(self.mix_addr)
                    self.handle_mix_fragment(packet)
                    continue

                if sock == self.sock_to_mix:
                    # collect mix fragments
                    packet = sock.recv(UDP_MTU)
                    self.handle_mix_fragment(packet)
                else:
                    # send responses to the mix chain
                    self.handle_response(sock)


# pylint: disable=C0103
if __name__ == "__main__":
    parser = AP(description="Receives data on the specified ip:port using " +
                "UDP and prints it on stdout.")
    parser.add_argument("ip:port", help="IP and Port pair to listen for " +
                        "datagrams on")

    args = parser.parse_args()

    own_addr = parse_ip_port(getattr(args, "ip:port"))
    print("Listening on {}:{}".format(*own_addr))
    print("Use Ctrl+C to quit.")

    exit_point = ExitPoint(own_addr)
    exit_point.run()
