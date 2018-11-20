from random import randint
from selectors import DefaultSelector, EVENT_READ
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from sphinxmix.SphinxClient import Nenc, create_forward_message, pack_message, PFdecode, unpack_message, Relay_flag, \
    receive_forward, Dest_flag
from sphinxmix.SphinxNode import sphinx_process

from Crypto.Random import get_random_bytes
from MixMessage import FRAG_SIZE, MixMessageStore, make_fragments, PACKET_SIZE
from constants import CHAN_ID_SIZE, MIN_PORT, MAX_PORT, UDP_MTU, \
    CTR_PREFIX_LEN, \
    CTR_MODE_PADDING, IPV4_LEN, PORT_LEN, CHAN_INIT_MSG_FLAG, DATA_MSG_FLAG, \
    CHAN_CONFIRM_MSG_FLAG, FLAG_LEN, REPLAY_WINDOW_SIZE, SPHINX_PARAMS
from util import i2b, b2i, padded, random_channel_id, cut, b2ip, ip2b, \
    gen_ctr_prefix, gen_sym_key, ctr_cipher

params = SPHINX_PARAMS
params_dict = {(params.max_len, params.m): params}


class ChannelEntry:
    out_chan_list = []
    to_mix = []
    to_client = []
    table = dict()

    def __init__(self, src_addr, dest_addr, pub_comps, mix_count=3):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.chan_id = ChannelEntry.random_channel()

        self.pub_comps = pub_comps

        print("New ChannelEntry for:", src_addr, dest_addr, "->", self.chan_id)

        ChannelEntry.table[self.chan_id] = self

        self.keys = []
        self.counters = []

        for _ in range(mix_count):
            self.keys.append(gen_sym_key())
            self.counters.append(gen_ctr_prefix())

        self.packets = []
        self.mix_msg_store = MixMessageStore()

        self.allowed_to_send = False

    def chan_init_msg(self):
        """The bytes in keys are assumed to be the resident keys of the mixes
        in reverse order of delivery (last mix first). The keys might be
        asymmetric keys in the future. These will be used to encrypt the
        channel init message and the channel keys that the client decided on.
        """
        # since we don't need the addresses, we use them to distribute the keys
        # the first key is never used, since we send it to the first mix directly
        # the last mix has to get the key from the payload
        keys = [b""] + self.keys[:2]

        ip, port = self.dest_addr

        # destination of the channel and the sym key for the last mix
        destination = ip2b(ip) + i2b(port, PORT_LEN) + self.keys[-1]

        routing_info = [Nenc(key) for key in keys]

        payload = b""

        header, delta = create_forward_message(params, routing_info, self.pub_comps, destination, payload)

        chan_init = pack_message(params, (header, delta))

        # we add a random ctr prefix, because the link encryption expects there
        # to be one, even though the channel init wasn't sym encrypted
        print("Len init:", len(pack_message(params, (header, delta))))

        return CHAN_INIT_MSG_FLAG + i2b(self.chan_id, CHAN_ID_SIZE) + get_random_bytes(
            CTR_PREFIX_LEN) + chan_init

    def chan_confirm_msg(self):
        if not self.allowed_to_send:
            print("Chan", self.chan_id, "is now allowed to send.")

        self.allowed_to_send = True

    def make_request_fragments(self, request):
        packet = []
        for fragment in make_fragments(request):
            packet = self.encrypt_fragment(fragment)

            self.packets.append(
                DATA_MSG_FLAG + i2b(self.chan_id, CHAN_ID_SIZE) + packet)

        print(self.src_addr, "->", self.chan_id, "len:", len(request), "->",
              len(packet))

    def recv_response_fragment(self, response):
        fragment = self.decrypt_fragment(response)

        # the endpoint adds a ctr prefix of zeroes, which we need to get rid of
        _, fragment = cut(fragment, CTR_PREFIX_LEN)

        self.mix_msg_store.parse_fragment(fragment)

    def get_completed_responses(self):
        packets = self.mix_msg_store.completed()

        self.mix_msg_store.remove_completed()

        return packets

    def encrypt_fragment(self, fragment):
        self.counters = [ctr + 1 for ctr in self.counters]

        for key, ctr_start in zip(reversed(self.keys), self.counters):
            cipher = ctr_cipher(key, ctr_start)

            fragment = i2b(ctr_start, CTR_PREFIX_LEN) + \
                cipher.encrypt(fragment)

        return fragment

    def decrypt_fragment(self, fragment):
        for key in self.keys:
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

        self.ctr_own = None
        self.ctr_next = None
        self.key = None

        self.last_prev_ctrs = []
        self.last_next_ctrs = []

        self.initialized = False

    def forward_request(self, request):
        """Takes a mix fragment, already stripped of the channel id."""
        ctr, cipher_text = cut(request, CTR_PREFIX_LEN)
        ctr = b2i(ctr)

        if not ChannelMid._check_replay_window(self.last_prev_ctrs, ctr):
            return

        cipher = ctr_cipher(self.key, ctr)

        forward_msg = cipher.decrypt(cipher_text) + get_random_bytes(CTR_MODE_PADDING)

        print("data", self.in_chan_id, "->", self.out_chan_id, "len:", len(forward_msg))

        ChannelMid.requests.append(DATA_MSG_FLAG + i2b(self.out_chan_id, CHAN_ID_SIZE) + forward_msg)

    def forward_response(self, response):
        # cut the padding off
        response, _ = cut(response, -CTR_MODE_PADDING)

        msg_type, response = cut(response, FLAG_LEN)

        if self.last_next_ctrs[-1] != 0:  # if this is 0 don't check for a ctr
            ctr, _ = cut(response, CTR_PREFIX_LEN)
            ctr_int = b2i(ctr)

            if not ChannelMid._check_replay_window(self.last_next_ctrs,
                                                   ctr_int):
                print("Caught replay detection for", self.out_chan_id)
                return

        cipher = ctr_cipher(self.key, self.ctr_own)

        forward_msg = cipher.encrypt(response)

        response = msg_type + i2b(self.in_chan_id, CHAN_ID_SIZE) + i2b(
            self.ctr_own, CTR_PREFIX_LEN) + forward_msg

        self.ctr_own += 1

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
        px, (header, delta) = unpack_message(params_dict, channel_init)

        ret = sphinx_process(params, priv_comp, header, delta)
        (tag, info, (header, delta), mac_key) = ret

        routing = PFdecode(params, info)

        if routing[0] == Relay_flag:
            flag, sym_key = routing
            cipher_text = pack_message(params, (header, delta))
        elif routing[0] == Dest_flag:
            dest_and_sym_key, msg = receive_forward(params, mac_key, delta)

            dest, sym_key = cut(dest_and_sym_key, IPV4_LEN + PORT_LEN)
            cipher_text = dest
        else:
            raise Exception()

        if self.key is not None:
            assert self.key == sym_key
            self.initialized = True
        else:
            self.key = sym_key

        self.ctr_own = 0
        self.ctr_next = 0
        self.last_prev_ctrs = [self.ctr_own] * REPLAY_WINDOW_SIZE
        self.last_next_ctrs = [self.ctr_next] * REPLAY_WINDOW_SIZE

        print("init", self.in_chan_id, "->", self.out_chan_id, "len:", len(cipher_text))

        # we add an empty ctr prefix, because the link encryption expects there
        # to be one, even though the channel init wasn't sym encrypted
        packet = CHAN_INIT_MSG_FLAG + i2b(self.out_chan_id, CHAN_ID_SIZE) + get_random_bytes(CTR_PREFIX_LEN) + padded(cipher_text, PACKET_SIZE)

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
        self.padding = 0

        self.mix_msg_store = MixMessageStore()
        ChannelExit.table[in_chan_id] = self

    def recv_request(self, request):
        """The mix fragment gets added to the fragment store. If the channel id
        is not already known a socket will be created for the destination of the
        mix fragment and added to the socket table.
        If the fragment completes the mix message, all completed mix messages
        will be sent out over their sockets.
        """

        self.padding = len(request) - FRAG_SIZE

        fragment, _ = cut(request, FRAG_SIZE)  # cut off any padding

        self.mix_msg_store.parse_fragment(fragment)

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

        mix_frags = make_fragments(data)

        for frag in mix_frags:
            packet = padded(frag, PACKET_SIZE)

            print("data", self.in_chan_id, "<-", self.dest_addr, "len:", len(packet))

            ChannelExit.to_mix.append(DATA_MSG_FLAG + i2b(self.in_chan_id, CHAN_ID_SIZE) +
                                      packet)

    def parse_channel_init(self, channel_init):
        ip, port, _ = cut(channel_init, IPV4_LEN, PORT_LEN)

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

    def send_chan_confirm(self):
        print("init", self.in_chan_id, "<-", self.dest_addr, "len:", PACKET_SIZE)
        ChannelExit.to_mix.append(CHAN_CONFIRM_MSG_FLAG + i2b(self.in_chan_id, CHAN_ID_SIZE) +
                                  get_random_bytes(PACKET_SIZE))

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
