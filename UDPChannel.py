from random import randint
from selectors import DefaultSelector, EVENT_READ
from socket import socket, AF_INET, SOCK_DGRAM as UDP, SOCK_STREAM
from time import time

from Counter import Counter
from MixMessage import DATA_FRAG_SIZE, MixMessageStore, DATA_PACKET_SIZE, FragmentGenerator, \
    make_dummy_init_fragment, make_dummy_data_fragment
from MsgV3 import gen_init_msg, process, cut_init_message
from ReplayDetection import ReplayDetector, ReplayDetectedError
from constants import CHAN_ID_SIZE, MIN_PORT, MAX_PORT, CTR_PREFIX_LEN, \
    IPV4_LEN, PORT_LEN, CHAN_INIT_MSG_FLAG, DATA_MSG_FLAG, \
    CHAN_CONFIRM_MSG_FLAG, MSG_TYPE_FLAG_LEN, CHANNEL_CTR_START, CHANNEL_TIMEOUT_SEC
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


def create_packet(channel_id, message_type, message_counter, payload):

    if isinstance(message_counter, Counter):
        message_counter = bytes(message_counter)

    return i2b(channel_id, CHAN_ID_SIZE) + message_type + message_counter + payload


class ChannelEntry:
    out_chan_list = []
    to_mix = []
    to_client = []
    table = dict()

    def __init__(self, src_addr, dest_addr, pub_comps):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.chan_id = ChannelEntry.random_channel()

        self.pub_comps = pub_comps

        print(self, "New Channel", self.dest_addr)

        ChannelEntry.table[self.chan_id] = self

        self.req_sym_keys = []
        self.res_sym_keys = []
        self.request_counter = Counter(CHANNEL_CTR_START)
        self.replay_detector = ReplayDetector(start=CHANNEL_CTR_START)

        for _ in self.pub_comps:
            self.req_sym_keys.append(gen_sym_key())
            self.res_sym_keys.append(gen_sym_key())

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

        channel_init = gen_init_msg(self.pub_comps, self.request_counter.current_value, self.req_sym_keys, self.res_sym_keys,
                                    destination + fragment)

        print(self, "Init", "->", len(channel_init))

        # we send a counter value with init messages for channel replay detection only
        return create_packet(self.chan_id, CHAN_INIT_MSG_FLAG, self.request_counter, channel_init)

    def _get_data_message(self):
        # todo make into generator
        fragment = self._get_data_fragment()

        message_counter, payload = cut(fragment, CTR_PREFIX_LEN)

        print(self, "Data", "->", len(payload))

        return create_packet(self.chan_id, DATA_MSG_FLAG, message_counter, payload)

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
        counter = self.request_counter

        for key in reversed(self.req_sym_keys):

            cipher = ctr_cipher(key, int(counter))

            fragment = cipher.encrypt(fragment)

        return bytes(counter) + fragment

    def _decrypt_fragment(self, fragment):
        ctr, cipher_text = cut(fragment, CTR_PREFIX_LEN)

        ctr = b2i(ctr)

        for key in self.res_sym_keys:
            cipher = ctr_cipher(key, ctr)

            cipher_text = cipher.decrypt(cipher_text)

        self.replay_detector.check_replay_window(ctr)

        return cipher_text

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

    def __init__(self, in_chan_id, address, check_responses=True):
        self.in_chan_id = in_chan_id
        self.out_chan_id = ChannelMid.random_channel()

        self.address = address

        print(self, "New Channel")

        ChannelMid.table_out[self.out_chan_id] = self
        ChannelMid.table_in[(address, self.in_chan_id)] = self

        self.req_key = None
        self.res_key = None
        self.request_replay_detector = ReplayDetector(start=CHANNEL_CTR_START)
        if check_responses:
            self.response_replay_detector = ReplayDetector(start=CHANNEL_CTR_START)
        else:
            self.response_replay_detector = None

        self.last_interaction = time()

        self.initialized = False

    def forward_request(self, request):
        """Takes a mix fragment, already stripped of the channel id."""
        self.last_interaction = time()

        ctr, cipher_text = cut(request, CTR_PREFIX_LEN)

        try:
            self.request_replay_detector.check_replay_window(b2i(ctr))

            cipher = ctr_cipher(self.req_key, b2i(ctr))

            payload = cipher.decrypt(cipher_text)

            print(self, "Data", "->", len(payload))

            packet = create_packet(self.out_chan_id, DATA_MSG_FLAG, ctr, payload)

            ChannelMid.requests.append(packet)

        except ReplayDetectedError:
            print("Detected Replay on channel", self.in_chan_id, "for counter", b2i(ctr))

        timed_out = check_for_timed_out_channels(ChannelMid.table_in)

        for in_id in timed_out:
            out_id = ChannelMid.table_in[in_id].out_chan_id

            del ChannelMid.table_in[in_id]
            del ChannelMid.table_out[out_id]

    def forward_response(self, response):
        self.last_interaction = time()

        msg_type, response = cut(response, MSG_TYPE_FLAG_LEN)

        msg_ctr, response = cut(response, CTR_PREFIX_LEN)

        if self.response_replay_detector is not None:
            self.response_replay_detector.check_replay_window(b2i(msg_ctr))

        cipher = ctr_cipher(self.res_key, b2i(msg_ctr))

        forward_msg = cipher.encrypt(response)

        print(self, "Data", "<-", len(forward_msg))

        response = create_packet(self.in_chan_id, msg_type, msg_ctr, forward_msg)

        ChannelMid.responses.append((self.address, response))

    def parse_channel_init(self, channel_init, priv_comp):
        """Takes an already decrypted channel init message and reads the key.
        """
        self.last_interaction = time()

        msg_ctr, channel_init = cut(channel_init, CTR_PREFIX_LEN)

        try:
            self.request_replay_detector.check_replay_window(b2i(msg_ctr))
        except ReplayDetectedError:
            print("Detected Replay on channel", self.in_chan_id, "for counter", b2i(msg_ctr))
            return

        key_req, key_res, _, channel_init = process(priv_comp, b2i(msg_ctr), channel_init)

        if self.req_key is not None and self.res_key is not None:
            assert self.req_key == key_req
            assert self.res_key == key_res
        else:
            self.req_key = key_req
            self.res_key = key_res

        self.initialized = True

        print(self, "Init", "->", len(channel_init))

        # todo look at this one again
        packet = create_packet(self.out_chan_id, CHAN_INIT_MSG_FLAG, msg_ctr, channel_init)

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
        self.response_counter = Counter(CHANNEL_CTR_START)
        self.response_counter.count()

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

            self.response_counter.count()

            fragment = frag_gen.get_data_fragment()
            packet = create_packet(self.in_chan_id, DATA_MSG_FLAG, bytes(self.response_counter),
                                   fragment)

            ChannelExit.to_mix.append(packet)

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
        self.response_counter.count()
        packet = create_packet(self.in_chan_id, CHAN_CONFIRM_MSG_FLAG, bytes(self.response_counter),
                               get_random_bytes(DATA_PACKET_SIZE))

        print(self, "Init", "<-", "len:", len(packet))

        ChannelExit.to_mix.append(packet)

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


class ChannelLastMix:
    out_chan_list = []
    out_ports = []
    responses = []

    table = dict()

    sock_sel = DefaultSelector()

    def __init__(self, chan_id, destination):
        self.chan_id = chan_id
        self.to_vpn = ChannelLastMix.random_socket(destination)
        ChannelLastMix.sock_sel.register(self.to_vpn, EVENT_READ, data=self)

        print(self, "New Channel")

        ChannelLastMix.table[self.chan_id] = self

        self.req_key = None
        self.res_key = None
        self.request_replay_detector = ReplayDetector(start=CHANNEL_CTR_START)
        self.response_counter = Counter(CHANNEL_CTR_START)

        self.msg_store = MixMessageStore()

        self.last_interaction = time()

        self.initialized = False

    def send_requests(self):
        # send completed mix messages to the destination immediately
        for mix_message in self.msg_store.completed():
            print(self, "Data", "->", len(mix_message.payload))

            try:
                self.to_vpn.send(i2b(len(mix_message.payload), 4) + mix_message.payload)
            except BrokenPipeError as bpe:
                print(bpe)

        self.msg_store.remove_completed()

    def forward_request(self, request):
        """Takes a mix fragment, already stripped of the channel id."""
        self.last_interaction = time()

        ctr, cipher_text = cut(request, CTR_PREFIX_LEN)

        try:
            self.request_replay_detector.check_replay_window(b2i(ctr))

            cipher = ctr_cipher(self.req_key, b2i(ctr))

            payload = cipher.decrypt(cipher_text)

            print(self, "Data", "->", len(payload))

            fragment, _ = cut(payload, DATA_FRAG_SIZE)

            try:
                self.msg_store.parse_fragment(fragment)
            except ValueError:
                print(self, "Dummy Request received")
                return

            self.send_requests()

        except ReplayDetectedError:
            print("Detected Replay on channel", self.chan_id, "for counter", b2i(ctr))

        timed_out = check_for_timed_out_channels(ChannelLastMix.table)

        for channel_id in timed_out:
            channel = ChannelLastMix.table[channel_id]

            channel.to_vpn.close()

            del ChannelLastMix.table[channel_id]

    def forward_response(self, response):
        """Turns the response into a MixMessage and saves its fragments for
        later sending.
        """
        self.last_interaction = time()

        frag_gen = FragmentGenerator(response)

        while frag_gen:
            print(self, "Data fragment", "<-", len(frag_gen.udp_payload))

            self.response_counter.count()

            fragment = frag_gen.get_data_fragment()

            cipher = ctr_cipher(self.res_key, int(self.response_counter))

            fragment = cipher.encrypt(fragment)

            packet = create_packet(self.chan_id, DATA_MSG_FLAG, bytes(self.response_counter), fragment)

            ChannelLastMix.responses.append(packet)

    def parse_channel_init(self, channel_init, priv_comp):
        self.last_interaction = time()

        msg_ctr, channel_init = cut(channel_init, CTR_PREFIX_LEN)

        try:
            self.request_replay_detector.check_replay_window(b2i(msg_ctr))
        except ReplayDetectedError:
            print("Detected Replay on channel", self.chan_id, "for counter", b2i(msg_ctr))

        key_req, key_res, payload, _ = process(priv_comp, b2i(msg_ctr), channel_init)

        if self.req_key is not None and self.res_key is not None:
            assert self.req_key == key_req
            assert self.res_key == key_res
        else:
            self.req_key = key_req
            self.res_key = key_res

        print(self, "Init", "->", len(payload))

        ip, port, fragment = cut(payload, IPV4_LEN, PORT_LEN)

        if not self.initialized:
            connect_message = bytes([1, 4, 1]) + ip + port + bytes(2)

            try:
                self.to_vpn.send(connect_message)
            except BrokenPipeError as bpe:
                print(bpe)

        self.initialized = True

        try:
            print(len(fragment))
            self.msg_store.parse_fragment(fragment)
        except ValueError as v:
            print(self, "Dummy Request received:", v)
            return

        self.send_requests()

    def send_chan_confirm(self):
        self.response_counter.count()
        packet = create_packet(self.chan_id, CHAN_CONFIRM_MSG_FLAG, bytes(self.response_counter),
                               get_random_bytes(DATA_PACKET_SIZE))

        print(self, "Init", "<-", "len:", len(packet))

        ChannelLastMix.responses.append(packet)

    def __str__(self):
        return "ChannelLastMix {}:".format(self.chan_id)

    @staticmethod
    def random_socket(vpn_destination):
        """Returns a socket bound to a random port, that is not in use already.
        """

        while True:
            rand_port = randint(MIN_PORT, MAX_PORT)

            if rand_port in ChannelLastMix.out_ports:
                # Port already in use by us
                continue

            try:
                new_sock = socket(AF_INET, SOCK_STREAM)

                new_sock.connect(vpn_destination)
                new_sock.setblocking(False)

                ChannelLastMix.out_ports.append(rand_port)

                return new_sock
            except OSError:
                # Port already in use by another application, try a new one
                pass
