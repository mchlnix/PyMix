#!/usr/bin/python3
# standard library
from random import randint
from argparse import ArgumentParser as AP
from selectors import DefaultSelector, EVENT_READ
# own
from Mix import PACKET_SIZE, CHAN_ID_SIZE, get_chan_id, get_packet
from util import i2b
from util import parse_ip_port
from Receiver import get_udp as get_udp_receiver
from MixMessage import MixMessageStore, make_fragments
from TwoWayTable import TwoWayTable

UDP_MTU = 65535

def handle_mix_fragment(chan_id, fragment):
    """Takes a mix fragment + channel id of the last mix and separates them.
       The mix fragment gets added to the fragment store and the destination ip
       and port of the mix message is mapped to the channel id. If the fragment
       completes the mix message, all completed mix messages will be sent to
       their destinations."""

    mix_msg_ref = store.parse_fragment(fragment)

    if chan_id not in chan_table.channel_ids:
        # a new udp channel was opened, save mapping and create Receiver
        chan_table.dest_addr[chan_id] = mix_msg_ref.dest
        sock_table.socket[chan_id] = get_udp_receiver(("127.0.0.1", randint(50000, 60000)), blocking=False)#XXX
        sock_sel.register(sock_table.socket[chan_id], EVENT_READ)

    # send out the payload of completed MixMessages
    for message in store.completed():
        print(chan_id, "->", message.dest)
        # get the receiver object to send the message out over
        sock_table.socket[chan_id].sendto(message.payload, message.dest)

    # remove sent out messages
    store.remove_completed()


def handle_response(socket):
    """Turns the response into a MixMessage and adds its fragments to the list
       of packets to send to the mix"""
    # get response data to set socket.getaddr()
    response = socket.recv(UDP_MTU)

    chan_id = chan_table.channel_id[socket.getaddr()]

    print(chan_id, "<-", socket.getaddr())

    # got a response to a packet we sent out, so we need to match the src
    # with a channel id, fragment the message and send the fragments with
    # the channel id to the mix
    if mix_addr is None:
        raise Exception("The mix address is not yet known, but there is " +
                        "already a response for it. Invalid State.")

    # we don't know the actual ip_port of the recipient. the client app, will
    # get the response through the channel ids and will know where to send it
    mix_frags = make_fragments(response, *("0.0.0.0", 0))

    for frag in mix_frags:
        back_to_mix.append(i2b(chan_id, CHAN_ID_SIZE) + frag)

    # send responses to the mix chain
    for packet in back_to_mix:
        sock_to_mix.sendto(packet, mix_addr)

    # clear all sent responses
    back_to_mix.clear()


# pylint: disable=C0103
if __name__ == "__main__":
    parser = AP(description=
                "Receives data on the specified ip:port " +
                "using UDP and prints it on stdout.")
    parser.add_argument("ip:port", help=
                        "IP and Port pair to listen for datagrams on")

    args = parser.parse_args()

    print("Use Ctrl+C to quit.")

    own_addr = parse_ip_port(getattr(args, "ip:port"))
    print("Listening on {}:{}".format(*own_addr))

    mix_addr = None

    # a special container, which accepts mix fragments and reassembls them to
    # MixMessage objects. completed MixMessages can be queried and removed
    # their payload is the original unencrypted payload
    store = MixMessageStore()

    # a list of responses, which will be sent back to the mix chain to
    # ultimately reach the right client
    back_to_mix = []

    # look up tables to map channel ids to dest ips
    chan_table = TwoWayTable("channel_id", "dest_addr")

    # look up table to map sockets to destinations
    sock_table = TwoWayTable("socket", "dest_addr")

    sock_sel = DefaultSelector()

    sock_to_mix = get_udp_receiver(own_addr, blocking=False)

    sock_sel.register(sock_to_mix, EVENT_READ)

    try:
        while True:
            events = sock_sel.select()

            for key, _ in events:
                r = key.fileobj

                # we assume the first message we receive will be from the mix
                if mix_addr is None:
                    mix_addr = r.getaddr()

                if r.getaddr() == mix_addr:
                    # collect mix fragments
                    data = r.recv(UDP_MTU)
                    assert len(data) == PACKET_SIZE
                    channel_id = get_chan_id(data)
                    payload = get_packet(data)
                    handle_mix_fragment(channel_id, payload)
                else:
                    # send responses to the mix chain
                    handle_response(r)

    except KeyboardInterrupt as kbi:
        print("Received Ctrl+C, quitting.")
