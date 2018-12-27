from random import randint
from selectors import DefaultSelector, EVENT_READ
from socket import socket, AF_INET, SOCK_DGRAM as UDP
from time import time

from Counter import Counter
from MixMessage import DATA_FRAG_SIZE, MixMessageStore, DATA_PACKET_SIZE, FragmentGenerator, \
    make_dummy_init_fragment, make_dummy_data_fragment
from MsgV3 import gen_init_msg, process, cut_init_message
from ReplayDetection import ReplayDetector
from constants import CHAN_ID_SIZE, MIN_PORT, MAX_PORT, CTR_PREFIX_LEN, \
    CTR_MODE_PADDING, IPV4_LEN, PORT_LEN, CHAN_INIT_MSG_FLAG, DATA_MSG_FLAG, \
    CHAN_CONFIRM_MSG_FLAG, MSG_TYPE_FLAG_LEN, MIX_COUNT, CHANNEL_CTR_START, CHANNEL_TIMEOUT_SEC
from util import i2b, b2i, random_channel_id, cut, b2ip, gen_sym_key, ctr_cipher, \
    get_random_bytes, ip2b


def check_for_timed_out_channels(channel_table, timeout=CHANNEL_TIMEOUT_SEC, log_prefix="UDPChannel"):
    now = time()

    timed_out = []

    for channel_id in channel_table.keys():
        channel = channel_table[channel_id]

        channel_timed_out = (now - channel.last_interaction) > timeout

        if channel_timed_out:
            print(log_prefix, "Timeout for channel", channel_id)

            timed_out.append(channel_id)

    return timed_out


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

        print(self, "New Channel", self.dest_addr)

        ChannelEntry.table[self.chan_id] = self

        self.sym_keys = []
        self.request_counter = Counter(CHANNEL_CTR_START)
        self.replay_detector = ReplayDetector(start=CHANNEL_CTR_START)

        for _ in self.pub_comps:
            self.sym_keys.append(gen_sym_key())

        self.packets = []
        self.mix_msg_store = MixMessageStore()

        self.last_interaction = time()

        self.allowed_to_send = False

    def can_send(self):
        return self.packets

    def request(self, request):
        self.last_interaction = time()

        self._make_request_fragments(request)

    def response(self, response):
        self.last_interaction = time()

        msg_type, response = cut(response, MSG_TYPE_FLAG_LEN)

        if msg_type == CHAN_CONFIRM_MSG_FLAG:
            self._chan_confirm_msg()
        elif msg_type == DATA_MSG_FLAG:
            self._receive_response_fragment(response)

    def get_message(self):
        if self.allowed_to_send:
            ret = self._get_data_message()
        else:
            ret = self._get_init_message()

        self._clean_generator_list()

        return ret

    def get_completed_responses(self):
        packets = self.mix_msg_store.completed()

        self.mix_msg_store.remove_completed()

        for packet in packets:
            print(self, "Data", "<-", len(packet.payload))

        return packets

    def _get_init_message(self):
        self.request_counter.count()

        ip, port = self.dest_addr

        destination = ip2b(ip) + i2b(port, PORT_LEN)

        fragment = self._get_init_fragment()

        channel_init = gen_init_msg(self.pub_comps, self.sym_keys, destination + fragment)

        print(self, "Init", "->", len(channel_init))

        # we send a counter value with init messages for channel replay detection only
        return CHAN_INIT_MSG_FLAG + self.b_chan_id + bytes(self.request_counter) + channel_init

    def _get_data_message(self):
        # todo make into generator
        fragment = self._get_data_fragment()

        print(self, "Data", "->", len(fragment) - CTR_PREFIX_LEN)

        return DATA_MSG_FLAG + self.b_chan_id + fragment

    def _get_init_fragment(self):
        # todo make into generator
        if self.packets:
            init_fragment = self.packets[0].get_init_fragment()
        else:
            init_fragment = make_dummy_init_fragment()

        return init_fragment

    def _get_data_fragment(self):
        # todo make into generator
        if self.packets:
            fragment = self.packets[0].get_data_fragment()
        else:
            fragment = make_dummy_data_fragment()

        return self._encrypt_fragment(fragment)

    def _clean_generator_list(self):
        delete = []
        for i in range(len(self.packets)):
            if not self.packets[i]:
                delete.append(i)

        for generator in reversed(delete):
            del self.packets[generator]

    def _chan_confirm_msg(self):
        if not self.allowed_to_send:
            print(self, "Received channel confirmation")

        self.allowed_to_send = True

    def _make_request_fragments(self, request):
        generator = FragmentGenerator(request)

        self.packets.append(generator)

        timed_out = check_for_timed_out_channels(ChannelEntry.table, timeout=CHANNEL_TIMEOUT_SEC - 5)

        for channel_id in timed_out:
            del ChannelEntry.table[channel_id]

    def _receive_response_fragment(self, response):
        fragment = self._decrypt_fragment(response)

        try:
            self.mix_msg_store.parse_fragment(fragment)
        except ValueError:
            print(self, "Dummy Response received")
            return

    def _encrypt_fragment(self, fragment):
        self.request_counter.count()

        for key in reversed(self.sym_keys):
            counter = self.request_counter

            cipher = ctr_cipher(key, int(counter))

            fragment = bytes(counter) + cipher.encrypt(fragment)

        return fragment

    def _decrypt_fragment(self, fragment):
        ctr = 0

        for key in self.sym_keys:
            ctr, cipher_text = cut(fragment, CTR_PREFIX_LEN)

            ctr = b2i(ctr)

            cipher = ctr_cipher(key, ctr)

            fragment = cipher.decrypt(cipher_text)

        self.replay_detector.check_replay_window(ctr)

        return fragment

    def __str__(self):
        return "ChannelEntry {}:{} - {}:".format(*self.src_addr, self.chan_id)

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

    def __init__(self, in_chan_id, check_responses=True):
        self.in_chan_id = in_chan_id
        self.out_chan_id = ChannelMid.random_channel()

        print(self, "New Channel")

        ChannelMid.table_out[self.out_chan_id] = self
        ChannelMid.table_in[self.in_chan_id] = self

        self.key = None
        self.request_replay_detector = ReplayDetector(start=CHANNEL_CTR_START)
        if check_responses:
            self.response_replay_detector = ReplayDetector(start=CHANNEL_CTR_START)
        else:
            self.response_replay_detector = None

        self.response_counter = Counter(CHANNEL_CTR_START)

        self.last_interaction = time()

        self.initialized = False

    def forward_request(self, request):
        """Takes a mix fragment, already stripped of the channel id."""
        self.last_interaction = time()

        ctr, cipher_text = cut(request, CTR_PREFIX_LEN)
        ctr = b2i(ctr)

        self.request_replay_detector.check_replay_window(ctr)

        cipher = ctr_cipher(self.key, ctr)

        forward_msg = cipher.decrypt(cipher_text) + get_random_bytes(CTR_MODE_PADDING)

        print(self, "Data", "->", len(forward_msg) - CTR_PREFIX_LEN)

        ChannelMid.requests.append(DATA_MSG_FLAG + i2b(self.out_chan_id, CHAN_ID_SIZE) + forward_msg)

        timed_out = check_for_timed_out_channels(ChannelMid.table_in)

        for in_id in timed_out:
            out_id = ChannelMid.table_in[in_id].out_chan_id

            del ChannelMid.table_in[in_id]
            del ChannelMid.table_out[out_id]

    def forward_response(self, response):
        self.last_interaction = time()

        # cut the padding off
        response, _ = cut(response, -CTR_MODE_PADDING)

        msg_type, response = cut(response, MSG_TYPE_FLAG_LEN)

        msg_ctr, _ = cut(response, CTR_PREFIX_LEN)

        if self.response_replay_detector is not None:
            self.response_replay_detector.check_replay_window(b2i(msg_ctr))

        self.response_counter.count()

        cipher = ctr_cipher(self.key, int(self.response_counter))

        forward_msg = cipher.encrypt(response)

        print(self, "Data", "<-", len(forward_msg))

        response = msg_type + i2b(self.in_chan_id, CHAN_ID_SIZE) + bytes(self.response_counter) + forward_msg

        ChannelMid.responses.append(response)

    def parse_channel_init(self, channel_init, priv_comp):
        """Takes an already decrypted channel init message and reads the key.
        """
        self.last_interaction = time()

        msg_ctr, channel_init = cut(channel_init, CTR_PREFIX_LEN)

        self.request_replay_detector.check_replay_window(b2i(msg_ctr))

        sym_key, _, channel_init = process(priv_comp, channel_init)

        if self.key is not None:
            assert self.key == sym_key
            self.initialized = True
        else:
            self.key = sym_key

        print(self, "Init", "->", len(channel_init))

        channel_init = msg_ctr + channel_init

        # we add an empty ctr prefix, because the link encryption expects there
        # to be one, even though the channel init wasn't sym encrypted

        # todo look at this one again
        packet = CHAN_INIT_MSG_FLAG + i2b(self.out_chan_id, CHAN_ID_SIZE) + channel_init

        ChannelMid.requests.append(packet)

    def __str__(self):
        return "ChannelMid {} - {}:".format(self.in_chan_id, self.out_chan_id)

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

        self.dest_addr = ("0.0.0.0", 0)

        self.last_interaction = time()

        print(self, "New Channel")

        self.mix_msg_store = MixMessageStore()
        ChannelExit.table[in_chan_id] = self

    def recv_request(self, request):
        """The mix fragment gets added to the fragment store. If the channel id
        is not already known a socket will be created for the destination of the
        mix fragment and added to the socket table.
        If the fragment completes the mix message, all completed mix messages
        will be sent out over their sockets.
        """
        self.last_interaction = time()
        fragment, _ = cut(request, DATA_FRAG_SIZE)

        try:
            self.mix_msg_store.parse_fragment(fragment)
        except ValueError:
            print(self, "Dummy Request received")
            return

        # send completed mix messages to the destination immediately
        for mix_message in self.mix_msg_store.completed():
            print(self, "Data", "->", len(mix_message.payload))

            try:
                self.out_sock.send(mix_message.payload)
            except ConnectionRefusedError:
                print("Channel", self.in_chan_id, "with address", self.out_sock, "connection refused.")

        self.mix_msg_store.remove_completed()

        timed_out = check_for_timed_out_channels(ChannelExit.table)

        for channel_id in timed_out:
            del ChannelExit.table[channel_id]

    def recv_response(self, response):
        """Turns the response into a MixMessage and saves its fragments for
        later sending.
        """
        self.last_interaction = time()

        frag_gen = FragmentGenerator(response)

        while frag_gen:
            print(self, "Data", "<-", len(frag_gen.udp_payload))

            fragment = frag_gen.get_data_fragment()
            packet = fragment + get_random_bytes(MIX_COUNT * CTR_PREFIX_LEN)

            ChannelExit.to_mix.append(DATA_MSG_FLAG + i2b(self.in_chan_id, CHAN_ID_SIZE) + packet)

    def parse_channel_init(self, channel_init):
        self.last_interaction = time()
        _, _, payload = cut_init_message(channel_init)

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
        print(self, "Init", "->", len(channel_init))

        self.recv_request(fragment)

    def send_chan_confirm(self):
        print(self, "Init", "<-", "len:", DATA_PACKET_SIZE)
        ChannelExit.to_mix.append(CHAN_CONFIRM_MSG_FLAG + i2b(self.in_chan_id, CHAN_ID_SIZE) + bytes(CTR_PREFIX_LEN) + get_random_bytes(DATA_PACKET_SIZE))

    def __str__(self):
        return "ChannelExit {} - {}:{}:".format(self.in_chan_id, *self.dest_addr)

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
