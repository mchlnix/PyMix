from random import randint
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from selectors import DefaultSelector, EVENT_READ

from Crypto.Random import get_random_bytes

from constants import CHAN_ID_SIZE, MIN_PORT, MAX_PORT, UDP_MTU
from util import i2ip, ip2i, i2b, b2i, padded, random_channel_id
from MixMessage import FRAG_SIZE, MixMessageStore, make_fragments
from Ciphers.CBC_CS import CBC_CS, default_cipher


class ChannelEntry:
    out_chan_list = []
    to_mix = []
    to_client = []
    table = dict()

    def __init__(self, src_addr, dest_addr, mix_count=3):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.chan_id = ChannelEntry.random_channel()

        print("New ChannelEntry for:", src_addr, dest_addr, "->", self.chan_id)

        ChannelEntry.table[self.chan_id] = self

        self.keys = []

        for i in range(mix_count):
            self.keys.append(CBC_CS.gen_key())

        self.cipher = default_cipher(self.keys)

        self.packets = []
        self.mix_msg_store = MixMessageStore()

    def chan_init_msg(self, mix_ciphers):
        """The bytes in keys are assumed to be the resident keys of the mixes
        in reverse order of delivery (last mix first). The keys might be
        asymmetric keys in the future. These will be used to encrypt the
        channel init message and the channel keys that the client decided on.
        """
        # Key 1
        #   Key 2
        #     Key 3
        #       Destination Address

        ip, port = self.dest_addr
        plain = i2b(ip2i(ip), 4) + i2b(port, 2)

        max_input_len = 210

        for cipher, key in zip(mix_ciphers, reversed(self.keys)):
            cut_off = max_input_len - len(key)
            plain = cipher.encrypt(key + plain[0:cut_off]) + plain[cut_off:]

        plain = padded(plain, FRAG_SIZE)

        return i2b(self.chan_id, CHAN_ID_SIZE) + plain

    def make_request_fragments(self, request):
        print(self.src_addr, "->", self.chan_id, "len:", len(request))
        for fragment in make_fragments(request):
            packet = self.cipher.encrypt(self.cipher.prepare_data(fragment))

            ChannelEntry.to_mix.append(i2b(self.chan_id, 2) + packet)

    def recv_response_fragment(self, response):
        print(self.src_addr, "<-", self.chan_id, "len:", len(response))
        response = self.cipher.decrypt(response)

        fragment = self.cipher.finalize_data(response)

        self.mix_msg_store.parse_fragment(fragment)

    def get_completed_responses(self):
        packets = self.mix_msg_store.completed()

        self.mix_msg_store.remove_completed()

        return packets

    @staticmethod
    def random_channel():
        rand_id = random_channel_id()

        while rand_id in ChannelEntry.out_chan_list:
            rand_id = random_channel_id()

        ChannelEntry.out_chan_list.append(rand_id)

        return rand_id


class ChannelMid:
    out_chan_list = []
    requests = []
    responses = []

    table_out = dict()
    table_in = dict()

    def __init__(self, in_chan_id):
        self.in_chan_id = in_chan_id
        self.out_chan_id = ChannelMid.random_channel()
        print("New ChannelMid for:", in_chan_id, "->", self.out_chan_id)

        ChannelMid.table_out[self.out_chan_id] = self
        ChannelMid.table_in[self.in_chan_id] = self

        self.cipher = None

    def forward_request(self, request):
        """Takes a mix fragment, already stripped of the channel id."""
        print(self.in_chan_id, "->", self.out_chan_id)
        ChannelMid.requests.append(i2b(self.out_chan_id, 2) + self.cipher.decrypt(request))

    def forward_response(self, response):
        print(self.in_chan_id, "<-", self.out_chan_id)
        ChannelMid.responses.append(i2b(self.in_chan_id, 2) + self.cipher.encrypt(response))

    def parse_channel_init(self, channel_init):
        """Takes an already decrypted channel init message and reads the key.
        """
        print("Len:", len(channel_init))
        key = channel_init[0:16]
        cipher_text = channel_init[16:] + get_random_bytes(16)

        self.cipher = default_cipher([key])

        print(self.in_chan_id, "->", self.out_chan_id, "len:", len(cipher_text))

        ChannelMid.requests.append(i2b(self.out_chan_id, 2) + cipher_text)

    @staticmethod
    def random_channel():
        rand_id = random_channel_id()

        while rand_id in ChannelMid.table_out.keys():
            rand_id = random_channel_id()

        ChannelMid.out_chan_list.append(rand_id)

        return rand_id


class ChannelExit:
    out_ports = []
    sock_sel = DefaultSelector()
    to_mix = []

    table = dict()

    def __init__(self, in_chan_id):
        self.in_chan_id = in_chan_id
        self.out_sock = ChannelExit.random_socket()
        print("New ChannelExit for:", in_chan_id)

        self.dest_addr = None
        self.padding = 48

        self.mix_msg_store = MixMessageStore()
        ChannelExit.table[in_chan_id] = self

    def recv_request(self, request):
        """The mix fragment gets added to the fragment store. If the channel id is
        not already known a socket will be created for the destination of the
        mix fragment and added to the socket table.
        If the fragment completes the mix message, all completed mix messages
        will be sent out over their sockets.
        """
        fragment = request[0:-self.padding]
        print(self.in_chan_id, "->", self.dest_addr, "len:", len(fragment))

        self.mix_msg_store.parse_fragment(fragment)

        # send completed mix messages to the destination immediately
        for mix_message in self.mix_msg_store.completed():
            self.out_sock.send(mix_message.payload)

        self.mix_msg_store.remove_completed()

    def recv_response(self):
        """Turns the response into a MixMessage and saves its fragments for
        later sending.
        """
        data = self.out_sock.recv(UDP_MTU)
        print(self.in_chan_id, "<-", self.dest_addr, "len:", len(data))

        mix_frags = make_fragments(data)

        for frag in mix_frags:
            ChannelExit.to_mix.append(i2b(self.in_chan_id, CHAN_ID_SIZE) + padded(frag, FRAG_SIZE + self.padding))

    def parse_channel_init(self, channel_init):
        ip = i2ip(b2i(channel_init[0:4]))
        port = b2i(channel_init[4:6])  # TODO lose the magic numbers

        self.dest_addr = (ip, port)

        self.out_sock.connect(self.dest_addr)

        ChannelExit.sock_sel.register(self.out_sock, EVENT_READ, data=self)

    @staticmethod
    def random_socket():
        """Returns a socket bound to a random port, that is not in use already."""

        while True:
            rand_port = randint(MIN_PORT, MAX_PORT)

            if rand_port in ChannelExit.out_ports:
                # Port already in use by us
                continue

            try:
                new_sock = socket(AF_INET, UDP)
                new_sock.bind(("127.0.0.1", rand_port))
                new_sock.setblocking(False)

                ChannelExit.out_ports.append(rand_port)

                return new_sock
            except OSError:
                # Port already in use by another application, try a new one
                pass
