import math

from constants import DATA_FRAG_PAYLOAD_SIZE, INIT_OVERHEAD, DATA_OVERHEAD, INIT_FRAG_PAYLOAD_SIZE
from util import b2i, i2b, get_random_bytes, cut

#########################################
# MixMessage Fragment Format            #
#                                       #
# Encryption overhead         n*8 Bytes #
#                                       #
# Packet ID                     4 Bytes #
# Number of fragments           1 Byte  #
# Number of this fragment       1 Byte  #
# Number of padding bytes       2 Bytes #
# Payload                       x Bytes #
#########################################


FRAG_ID_SIZE = 4

FRAG_COUNT_SIZE = 1
FRAG_INDEX_SIZE = FRAG_COUNT_SIZE  # have to stay equal size
FRAG_PADDING_SIZE = 2

FRAG_FLAG_SIZE = 1
FRAG_HEADER_SIZE = FRAG_ID_SIZE + FRAG_FLAG_SIZE

MAX_FRAG_COUNT = 2 ** (FRAG_COUNT_SIZE * 8) - 1

HIGHEST_ID = 2 ** (FRAG_ID_SIZE * 8) - 1
LOWEST_ID = 1

DATA_FRAG_SIZE = FRAG_HEADER_SIZE + DATA_FRAG_PAYLOAD_SIZE
INIT_FRAG_SIZE = FRAG_HEADER_SIZE + INIT_FRAG_PAYLOAD_SIZE

DATA_PACKET_SIZE = DATA_OVERHEAD + DATA_FRAG_SIZE
INIT_PACKET_SIZE = INIT_OVERHEAD + INIT_FRAG_SIZE


class MixMessageStore:
    def __init__(self):
        self.packets = dict()

    def parse_fragment(self, raw_frag):
        msg_id, is_last, fragment_id, payload = parse_fragment(raw_frag)

        if len(payload) <= 0:
            raise ValueError("No payload bytes transmitted. Probably dummy traffic.")

        if msg_id in self.packets:
            packet = self.packets[msg_id]
        else:
            packet = MixMessage(msg_id)

        if is_last:
            packet.frag_count = fragment_id + 1

        packet.add_fragment(fragment_id, payload)

        self.packets[msg_id] = packet

        return self.packets[msg_id]

    def completed(self):
        return [packet for packet in self.packets.values() if packet.complete]

    def pop(self):
        for msg_id, packet in self.packets.items():
            if packet.complete:
                break
        else:
            raise IndexError("No completed packets.")

        # msg_id still exists after for loop
        msg_id, packet = self.packets.pop(msg_id)

        return packet

    def remove(self, msg_id):
        del self.packets[msg_id]

    def remove_completed(self):
        msg_ids = [packet.id for packet in self.completed()]

        for msg_id in msg_ids:
            self.remove(msg_id)


class MixMessage:
    def __init__(self, msg_id):
        self.fragments = dict()
        self.id = msg_id
        self.frag_count = 0
        self.payload_size = 0

    def add_fragment(self, frag_index, payload):
        if frag_index in self.fragments:
            return

        self.fragments[frag_index] = payload

    @property
    def complete(self):
        return len(self.fragments) == self.frag_count

    @property
    def payload(self):
        payload = bytes()
        if self.complete:
            for key in range(0, len(self.fragments)):
                payload += self.fragments[key]

        return payload

    def __str__(self):
        ret = ""
        ret += "MixMessage:  {}\n".format(self.id)
        ret += "Fragments:   {}/{}\n".format(len(self.fragments),
                                             self.frag_count)
        ret += "Size:        {}\n".format(self.payload_size)

        if self.complete:
            payload = ":".join("{:02x}".format(b) for b in self.payload[0:16])
            ret += "Payload:     {}...\n".format(payload)

        return ret


PADDING_SIZE = 2


def how_many_padding_bytes_necessary(padding_len):
    if padding_len in [0, 1]:
        return 1

    l2 = math.log2(padding_len)

    return math.ceil(l2/7)


def bytes_to_padding_length(padding_bytes):
    padding = 0
    bytes_read = 0

    for byte in padding_bytes:
        padding += byte & 0b0111_1111

        bytes_read += 1
        if byte & 0b1000_0000:
            break
        else:
            padding <<= 7

    return padding, bytes_read


def padding_length_to_bytes(padding_len):
    if padding_len < 0:
        raise ValueError("No negative padding lengths. Was", padding_len)

    if padding_len == 0:
        return bytes(), 0

    # get amount of padding bytes
    padding_bytes_len = how_many_padding_bytes_necessary(padding_len)
    padding_len -= padding_bytes_len

    ret_padding_len = padding_len

    padding_bytes = []

    while True:
        padding_bytes.append(padding_len % 0b1000_0000)
        padding_len >>= 7

        if padding_len <= 0:
            break

    padding_bytes[0] |= 0b1000_0000

    return bytes(padding_bytes_len - len(padding_bytes)) + bytes(reversed(padding_bytes)), ret_padding_len


def parse_fragment(fragment):
    msg_id, frag_byte, rest = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE)

    i_frag_byte = b2i(frag_byte)

    fragment_id = i_frag_byte & 0b0011_1111

    is_last = (i_frag_byte & FragmentGenerator.LAST_FRAG_FLAG) == FragmentGenerator.LAST_FRAG_FLAG

    payload_len = len(rest)

    has_padding = (i_frag_byte & FragmentGenerator.PADDING_FLAG) == FragmentGenerator.PADDING_FLAG

    if has_padding:
        padding_len, padding_bytes = bytes_to_padding_length(rest)

        payload_len -= (padding_len + padding_bytes)

        padding_bytes, payload, padding = cut(rest, padding_bytes, payload_len)
    else:
        payload = rest

    return b2i(msg_id), is_last, fragment_id, payload


def make_fragment(message_id, fragment_number, last_fragment, payload, payload_limit):
    if fragment_number > 0b0011_1111:
        raise ValueError("Too many fragments needed for this payload.")

    #if len(payload) == 0:
     #   raise ValueError("No more fragments left to generate.")

    frag_byte = fragment_number

    if last_fragment:
        frag_byte |= FragmentGenerator.LAST_FRAG_FLAG

    if len(payload) < payload_limit:
        frag_byte |= FragmentGenerator.PADDING_FLAG

        padding_bytes, padding_len = padding_length_to_bytes(payload_limit - len(payload))
    else:
        padding_len = 0
        padding_bytes = bytes()

    fragment = i2b(message_id, FRAG_ID_SIZE) + i2b(frag_byte, FRAG_FLAG_SIZE)

    fragment += padding_bytes

    fragment += payload[:payload_limit] + get_random_bytes(padding_len)

    return fragment


def make_dummy_data_fragment():
    return make_fragment(0x0, 0x0, True, bytes(0),
                         DATA_FRAG_PAYLOAD_SIZE)


def make_dummy_init_fragment():
    return make_fragment(0x0, 0x0, True, bytes(0),
                         INIT_FRAG_PAYLOAD_SIZE)


class FragmentGenerator:
    PADDING_FLAG = 0x80
    LAST_FRAG_FLAG = 0x40

    PADDING_BITMASK = 0x7F

    last_used_message_id = 0

    def __init__(self, udp_payload):
        self.udp_payload = udp_payload

        FragmentGenerator.last_used_message_id += 1
        self.message_id = FragmentGenerator.last_used_message_id

        self.current_fragment = 0

    def get_init_fragment(self):
        return self._build_fragment(INIT_FRAG_PAYLOAD_SIZE)

    def get_data_fragment(self):
        return self._build_fragment(DATA_FRAG_PAYLOAD_SIZE)

    def _build_fragment(self, payload_limit):
        is_last_fragment = len(self.udp_payload) <= payload_limit

        payload, self.udp_payload = cut(self.udp_payload, payload_limit)

        fragment_number = self.current_fragment
        self.current_fragment += 1

        return make_fragment(self.message_id, fragment_number, is_last_fragment, payload, payload_limit)

    def __bool__(self):
        return len(self.udp_payload) > 0
