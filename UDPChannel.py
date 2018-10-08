from random import randint
from selectors import DefaultSelector, EVENT_READ
from socket import socket, AF_INET, SOCK_DGRAM as UDP

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

from MixMessage import FRAG_SIZE, MixMessageStore, make_fragments
from constants import CHAN_ID_SIZE, MIN_PORT, MAX_PORT, UDP_MTU, REPLAY_WINDOW_SIZE, ASYM_INPUT_LEN, SYM_KEY_LEN, \
    CTR_PREFIX_LEN
from util import i2b, b2i, padded, random_channel_id, cut, b2ip, ip2b


def gen_key():
    return get_random_bytes(SYM_KEY_LEN)


def gen_ctr():
    return b2i(get_random_bytes(CTR_PREFIX_LEN))


def ctr_cipher(key, counter):
    # nbits = 8 bytes + prefix = 8 bytes
    ctr = Counter.new(nbits=64, prefix=i2b(counter, CTR_PREFIX_LEN))
    return AES.new(key, AES.MODE_CTR, counter=ctr)


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
        self.counters = []

        for i in range(mix_count):
            self.keys.append(gen_key())
            self.counters.append(gen_ctr())

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
        #     Destination Address

        ip, port = self.dest_addr
        plain = padded(ip2b(ip) + i2b(port, 2), ASYM_INPUT_LEN)

        cut_off = ASYM_INPUT_LEN - SYM_KEY_LEN - 2 * CTR_PREFIX_LEN

        # add 0 at the end, since the last mix doesn't need to check ctr values
        for cipher, key, ctr_start, ctr_check in zip(mix_ciphers,
                                                     reversed(self.keys),
                                                     self.counters,
                                                     [0] + self.counters[0:-1]):
            plain = cipher.encrypt(key +
                                   i2b(ctr_start, CTR_PREFIX_LEN) +
                                   i2b(ctr_check, CTR_PREFIX_LEN) +
                                   plain[0:cut_off]) + plain[cut_off:]

        plain = padded(plain, FRAG_SIZE)

        return i2b(self.chan_id, CHAN_ID_SIZE) + plain

    def make_request_fragments(self, request):
        print(self.src_addr, "->", self.chan_id, "len:", len(request))
        packet = []
        for fragment in make_fragments(request):
            packet = self.encrypt_fragment(fragment)

            ChannelEntry.to_mix.append(i2b(self.chan_id, CHAN_ID_SIZE) + packet)

        print(self.src_addr, "->", self.chan_id, "len:", len(packet))

    def recv_response_fragment(self, response):
        print(self.src_addr, "<-", self.chan_id, "len:", len(response))
        fragment = self.decrypt_fragment(response)

        self.mix_msg_store.parse_fragment(fragment)

    def get_completed_responses(self):
        packets = self.mix_msg_store.completed()

        self.mix_msg_store.remove_completed()

        return packets

    def encrypt_fragment(self, fragment):
        self.counters = [ctr + 1 for ctr in self.counters]

        for key, ctr_start in zip(reversed(self.keys), self.counters):
            cipher = ctr_cipher(key, ctr_start)

            fragment = i2b(ctr_start, CTR_PREFIX_LEN) + cipher.encrypt(fragment)

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

    def forward_request(self, request):
        """Takes a mix fragment, already stripped of the channel id."""
        print(self.in_chan_id, "->", self.out_chan_id, "len:", len(request))

        ctr, cipher_text = cut(request, CTR_PREFIX_LEN)
        ctr = b2i(ctr)

        if not ChannelMid._check_replay_window(self.last_prev_ctrs, ctr):
            return

        cipher = ctr_cipher(self.key, ctr)

        ChannelMid.requests.append(i2b(self.out_chan_id, 2) + cipher.decrypt(cipher_text))

    def forward_response(self, response):
        print(self.in_chan_id, "<-", self.out_chan_id, "len:", len(response))

        ctr, _ = cut(response, CTR_PREFIX_LEN)
        ctr = b2i(ctr)

        if not ChannelMid._check_replay_window(self.last_next_ctrs, ctr):
            return

        cipher = ctr_cipher(self.key, self.ctr_own)
        response = i2b(self.ctr_own, CTR_PREFIX_LEN) + cipher.encrypt(response)

        self.ctr_own += 1

        ChannelMid.responses.append(i2b(self.in_chan_id, CHAN_ID_SIZE) + response)

    @staticmethod
    def _check_replay_window(ctr_list, ctr):
        if ctr_list[-1]:  # if this is 0 don't check for a ctr
            if ctr in ctr_list:
                print("Already seen ctr value", ctr)
                return False
            elif ctr < ctr_list[0]:
                print("Ctr value", ctr, "too small")
                return False
            else:
                print("Valid ctr", ctr)

            ctr_list.append(ctr)

            # remove the smallest element
            ctr_list.sort()
            ctr_list.pop(0)

        return True

    def parse_channel_init(self, channel_init):
        """Takes an already decrypted channel init message and reads the key.
        """
        key_pos = 0
        ctr1_pos = 16
        ctr2_pos = 24
        payload_pos = SYM_KEY_LEN + 2 * CTR_PREFIX_LEN

        self.key = channel_init[key_pos:SYM_KEY_LEN]

        self.ctr_own = b2i(channel_init[ctr1_pos:ctr1_pos + CTR_PREFIX_LEN])
        self.ctr_next = b2i(channel_init[ctr2_pos:ctr2_pos + CTR_PREFIX_LEN])

        self.last_prev_ctrs = [self.ctr_own] * REPLAY_WINDOW_SIZE
        self.last_next_ctrs = [self.ctr_next] * REPLAY_WINDOW_SIZE

        # we increment the counter value, so we don't collide with the replay
        # detection
        self.ctr_own += 1

        cipher_text = channel_init[payload_pos:] + get_random_bytes(payload_pos)

        print(self.in_chan_id, "->", self.out_chan_id, "len:", len(cipher_text))
        print("Own ctr", self.ctr_own, "Next ctr", self.ctr_next)

        ChannelMid.requests.append(i2b(self.out_chan_id, CHAN_ID_SIZE) + cipher_text)

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
        """The mix fragment gets added to the fragment store. If the channel id is
        not already known a socket will be created for the destination of the
        mix fragment and added to the socket table.
        If the fragment completes the mix message, all completed mix messages
        will be sent out over their sockets.
        """
        print("Len:", len(request))
        fragment, _ = cut(request, FRAG_SIZE)  # cut off any padding
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
        ip, port, _ = cut(channel_init, 4, 6)  # TODO lose the magic numbers

        ip = b2ip(ip)
        port = b2i(port)

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
