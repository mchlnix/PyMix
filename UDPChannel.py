from random import randint
from selectors import DefaultSelector, EVENT_READ
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from MixMessage import FRAG_SIZE, MixMessageStore, DATA_PACKET_SIZE, FragmentGenerator, \
    make_dummy_init_fragment, make_dummy_data_fragment
from MsgV3 import gen_init_msg, process
from constants import CHAN_ID_SIZE, MIN_PORT, MAX_PORT, UDP_MTU, \
    CTR_PREFIX_LEN, \
    CTR_MODE_PADDING, IPV4_LEN, PORT_LEN, CHAN_INIT_MSG_FLAG, DATA_MSG_FLAG, \
    CHAN_CONFIRM_MSG_FLAG, FLAG_LEN
from util import i2b, b2i, padded, random_channel_id, cut, b2ip, gen_ctr_prefix, gen_sym_key, ctr_cipher, \
    get_random_bytes, ip2b


class ChannelEntry:
    out_chan_list = []
    to_mix = []
    to_client = []
    table = dict()

    def __init__(self, src_addr, dest_addr, pub_comps):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.chan_id = ChannelEntry.random_channel()
        self.b_chan_id = i2b(self.chan_id, CHAN_ID_SIZE)

        self.pub_comps = pub_comps

        print("New ChannelEntry for:", src_addr, dest_addr, "->", self.chan_id)

        ChannelEntry.table[self.chan_id] = self

        self.sym_keys = []

        for _ in self.pub_comps:
            self.sym_keys.append(gen_sym_key())

        self.packets = []
        self.mix_msg_store = MixMessageStore()

        self.allowed_to_send = False

    def chan_init_msg(self):
        """The bytes in keys are assumed to be the resident keys of the mixes
        in reverse order of delivery (last mix first). The keys might be
        asymmetric keys in the future. These will be used to encrypt the
        channel init message and the channel keys that the client decided on.
        """
        ip, port = self.dest_addr

        # destination of the channel and the sym key for the last mix
        destination = ip2b(ip) + i2b(port, PORT_LEN)

        fragment = self.get_init_fragment()
        chan_init = gen_init_msg(self.pub_comps, self.sym_keys, destination + fragment)

        # we add a random ctr prefix, because the link encryption expects there
        # to be one, even though the channel init wasn't sym encrypted
        return CHAN_INIT_MSG_FLAG + self.b_chan_id + get_random_bytes(
            CTR_PREFIX_LEN) + chan_init

    def get_data_message(self):
        # todo make into generator
        return DATA_MSG_FLAG + self.b_chan_id + get_random_bytes(CTR_PREFIX_LEN) + self.get_data_fragment()

    def get_init_fragment(self):
        # todo make into generator
        self.clean_generator_list()

        if self.packets:
            return self.packets[0].get_init_fragment()

        return make_dummy_init_fragment()

    def get_data_fragment(self):
        # todo make into generator
        self.clean_generator_list()

        if self.packets:
            return self.packets[0].get_data_fragment()
        else:
            return make_dummy_data_fragment()

    def clean_generator_list(self):
        delete = []
        for i in range(len(self.packets)):
            if not self.packets[i]:
                delete.append(i)

        for generator in reversed(delete):
            del self.packets[generator]

    def chan_confirm_msg(self):
        if not self.allowed_to_send:
            print("Chan", self.chan_id, "is now allowed to send.")

        self.allowed_to_send = True

    def make_request_fragments(self, request):
        generator = FragmentGenerator(request)

        self.packets.append(generator)

    def recv_response_fragment(self, response):
        fragment = self.decrypt_fragment(response)

        try:
            self.mix_msg_store.parse_fragment(fragment)
        except ValueError:
            return

    def get_completed_responses(self):
        packets = self.mix_msg_store.completed()

        self.mix_msg_store.remove_completed()

        return packets

    def encrypt_fragment(self, fragment):
        for key in reversed(self.sym_keys):
            counter = gen_ctr_prefix()

            cipher = ctr_cipher(key, counter)

            fragment = i2b(counter, CTR_PREFIX_LEN) + cipher.encrypt(fragment)

        return fragment

    def decrypt_fragment(self, fragment):
        for key in self.sym_keys:
            ctr, cipher_text = cut(fragment, CTR_PREFIX_LEN)

            cipher = ctr_cipher(key, b2i(ctr))

            fragment = cipher.decrypt(cipher_text)

        return fragment

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

        self.key = None

        self.initialized = False

    def forward_request(self, request):
        """Takes a mix fragment, already stripped of the channel id."""
        ctr, cipher_text = cut(request, CTR_PREFIX_LEN)
        ctr = b2i(ctr)

        cipher = ctr_cipher(self.key, ctr)

        forward_msg = cipher.decrypt(cipher_text) + get_random_bytes(CTR_MODE_PADDING)

        print("data", self.in_chan_id, "->", self.out_chan_id, "len:", len(forward_msg))

        ChannelMid.requests.append(DATA_MSG_FLAG + i2b(self.out_chan_id, CHAN_ID_SIZE) + forward_msg)

    def forward_response(self, response):
        # cut the padding off
        response, _ = cut(response, -CTR_MODE_PADDING)

        msg_type, response = cut(response, FLAG_LEN)

        counter = gen_ctr_prefix()
        cipher = ctr_cipher(self.key, counter)

        forward_msg = cipher.encrypt(response)

        response = msg_type + i2b(self.in_chan_id, CHAN_ID_SIZE) + i2b(counter, CTR_PREFIX_LEN) + forward_msg

        print("data", self.in_chan_id, "<-", self.out_chan_id, "len:", len(forward_msg))

        ChannelMid.responses.append(response)

    @staticmethod
    def _check_replay_window(ctr_list, ctr):
        if ctr in ctr_list:
            raise Exception("Already seen ctr value", ctr)
        elif ctr < ctr_list[0]:
            raise Exception("Ctr value", ctr, "too small")

        ctr_list.append(ctr)

        # remove the smallest element
        ctr_list.sort()
        ctr_list.pop(0)

        return True

    def parse_channel_init(self, channel_init, priv_comp):
        """Takes an already decrypted channel init message and reads the key.
        """

        sym_key, payload, channel_init = process(priv_comp, channel_init)

        if self.key is not None:
            assert self.key == sym_key
            self.initialized = True
        else:
            self.key = sym_key

        print("init", self.in_chan_id, "->", self.out_chan_id, "len:", len(channel_init))

        # we add an empty ctr prefix, because the link encryption expects there
        # to be one, even though the channel init wasn't sym encrypted

        # todo look at this one again
        packet = CHAN_INIT_MSG_FLAG + i2b(self.out_chan_id, CHAN_ID_SIZE) + get_random_bytes(CTR_PREFIX_LEN) + padded(channel_init, DATA_PACKET_SIZE)

        ChannelMid.requests.append(packet)

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

        self.mix_msg_store = MixMessageStore()
        ChannelExit.table[in_chan_id] = self

    def recv_request(self, request):
        """The mix fragment gets added to the fragment store. If the channel id
        is not already known a socket will be created for the destination of the
        mix fragment and added to the socket table.
        If the fragment completes the mix message, all completed mix messages
        will be sent out over their sockets.
        """
        fragment, _ = cut(request, FRAG_SIZE)  # cut off any padding

        try:
            self.mix_msg_store.parse_fragment(fragment)
        except ValueError:
            return

        # send completed mix messages to the destination immediately
        for mix_message in self.mix_msg_store.completed():
            print("data", self.in_chan_id, "->", self.dest_addr, "len:", len(mix_message.payload))
            self.out_sock.send(mix_message.payload)

        self.mix_msg_store.remove_completed()

    def recv_response(self):
        """Turns the response into a MixMessage and saves its fragments for
        later sending.
        """
        data = self.out_sock.recv(UDP_MTU)

        frag_gen = FragmentGenerator(data)

        while frag_gen:
            fragment = frag_gen.get_data_fragment()
            packet = padded(fragment, DATA_PACKET_SIZE)

            print("data", self.in_chan_id, "<-", self.dest_addr, "len:", len(packet))

            ChannelExit.to_mix.append(DATA_MSG_FLAG + i2b(self.in_chan_id, CHAN_ID_SIZE) + packet)

    def parse_channel_init(self, channel_init):
        _, _, payload = cut(channel_init, 29, 48)

        ip, port, fragment = cut(payload, IPV4_LEN, PORT_LEN)

        ip = b2ip(ip)
        port = b2i(port)

        self.dest_addr = (ip, port)

        try:
            self.out_sock.connect(self.dest_addr)
        except OSError:
            # couldn't connect, maybe not a channel init message?
            print("Couldn't connect to destination. Dropped message.")
            self.out_sock.close()
            del ChannelExit.table[self.in_chan_id]

            return

        ChannelExit.sock_sel.register(self.out_sock, EVENT_READ, data=self)
        print("init", self.in_chan_id, "->", self.dest_addr, "len:", len(channel_init))

        self.recv_request(fragment)

    def send_chan_confirm(self):
        print("init", self.in_chan_id, "<-", self.dest_addr, "len:", DATA_PACKET_SIZE)
        ChannelExit.to_mix.append(CHAN_CONFIRM_MSG_FLAG + i2b(self.in_chan_id, CHAN_ID_SIZE) + bytes(CTR_PREFIX_LEN) +
                                  get_random_bytes(DATA_PACKET_SIZE))

    @staticmethod
    def random_socket():
        """Returns a socket bound to a random port, that is not in use already.
        """

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
