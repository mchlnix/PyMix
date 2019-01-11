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


FRAG_ID_SIZE = 2
DUMMY_FRAG_ID = 0

FRAG_COUNT_SIZE = 1
FRAG_INDEX_SIZE = FRAG_COUNT_SIZE  # have to stay equal size
FRAG_PADDING_SIZE = 2

FRAG_FLAG_SIZE = 1
FRAG_HEADER_SIZE = FRAG_ID_SIZE + FRAG_FLAG_SIZE

MAX_FRAG_COUNT = 2 ** (FRAG_COUNT_SIZE * 8) - 1

HIGHEST_ID = 2 ** (FRAG_ID_SIZE * 8 - 2) - 1  # - 2 for last_frag and has_padding flags
LOWEST_ID = 1

SINGLE_FRAGMENT_MESSAGE_ID = 0

DATA_FRAG_SIZE = FRAG_HEADER_SIZE + DATA_FRAG_PAYLOAD_SIZE
INIT_FRAG_SIZE = FRAG_HEADER_SIZE + INIT_FRAG_PAYLOAD_SIZE

DATA_PACKET_SIZE = DATA_OVERHEAD + DATA_FRAG_SIZE
INIT_PACKET_SIZE = INIT_OVERHEAD + INIT_FRAG_SIZE

assert DATA_PACKET_SIZE == INIT_PACKET_SIZE


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
                msg_id, packet = self.packets.pop(msg_id)

                return packet

        raise IndexError("No completed packets.")

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

    return math.ceil(l2 / 7)


def bytes_to_padding_length(padding_bytes):
    padding = 0
    bytes_read = 0

    for byte in padding_bytes:
        padding += byte & FragmentGenerator.PADDING_BITMASK

        bytes_read += 1
        if byte & FragmentGenerator.PADDING_DONE_FLAG:
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
        padding_bytes.append(padding_len % FragmentGenerator.PADDING_DONE_FLAG)
        padding_len >>= 7

        if padding_len <= 0:
            break

    padding_bytes[0] |= FragmentGenerator.PADDING_DONE_FLAG

    return bytes(padding_bytes_len - len(padding_bytes)) + bytes(reversed(padding_bytes)), ret_padding_len


def parse_fragment(fragment):
    b_msg_id, rest = cut(fragment, FRAG_ID_SIZE)

    message_id = b2i(b_msg_id)

    last_fragment = bool(message_id & FragmentGenerator.LAST_FRAG_FLAG)
    has_padding = message_id & FragmentGenerator.PADDING_FLAG

    message_id >>= 2

    if message_id != SINGLE_FRAGMENT_MESSAGE_ID:
        frag_byte, rest = cut(rest, FRAG_FLAG_SIZE)
        fragment_id = b2i(frag_byte)
    else:
        fragment_id = 0

    payload_len = len(rest)

    if has_padding:
        padding_len, padding_bytes = bytes_to_padding_length(rest)

        payload_len -= (padding_len + padding_bytes)

        _, payload, _ = cut(rest, padding_bytes, payload_len)
    else:
        payload = rest

    return message_id, last_fragment, fragment_id, payload


def make_fragment(message_id, fragment_number, last_fragment, payload, payload_limit):
    """
        14 Bit message id
         1 Bit last fragment flag
         1 Bit has padding flag
         8 Bit fragment number (starting at 0)
         0 - 16 Bit Padding size
         x Byte Payload
         y Byte Padding
    """
    if fragment_number > MAX_FRAG_COUNT:
        raise ValueError("Too many fragments needed for this payload.")

    if not payload and message_id != DUMMY_FRAG_ID:
        raise ValueError("No more fragments left to generate.")

    if message_id > HIGHEST_ID:
        raise ValueError("Message ID too high.", message_id)

    no_frag_number_necessary = fragment_number == 0 and len(payload) <= payload_limit + 1

    if no_frag_number_necessary:
        frag_byte = bytes(0)
        payload_limit += 1
        message_id = SINGLE_FRAGMENT_MESSAGE_ID
        last_fragment = True
    else:
        frag_byte = i2b(fragment_number, FRAG_FLAG_SIZE)

    message_id <<= 2

    if last_fragment:
        message_id |= FragmentGenerator.LAST_FRAG_FLAG

    if len(payload) < payload_limit:
        message_id |= FragmentGenerator.PADDING_FLAG

        padding_bytes, padding_len = padding_length_to_bytes(payload_limit - len(payload))
    else:
        padding_len = 0
        padding_bytes = bytes()

    fragment = i2b(message_id, FRAG_ID_SIZE) + frag_byte

    fragment += padding_bytes

    fragment += payload[:payload_limit] + get_random_bytes(padding_len)

    return fragment, payload_limit - (len(padding_bytes) + padding_len)


def make_dummy_data_fragment():
    return make_fragment(0x0, 0x0, True, bytes(0),
                         DATA_FRAG_PAYLOAD_SIZE)[0]


def make_dummy_init_fragment():
    return make_fragment(0x0, 0x0, True, bytes(0),
                         INIT_FRAG_PAYLOAD_SIZE)[0]


class FragmentGenerator:
    PADDING_FLAG = 0b0000_0000_0000_0001
    LAST_FRAG_FLAG = 0b0000_0000_0000_0010

    PADDING_BITMASK = 0b0111_1111
    PADDING_DONE_FLAG = 0b1000_0000

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

        fragment_number = self.current_fragment
        self.current_fragment += 1

        fragment, payload_len = make_fragment(self.message_id, fragment_number, is_last_fragment, self.udp_payload,
                                              payload_limit)

        self.udp_payload = self.udp_payload[payload_len:]

        return fragment

    def __bool__(self):
        return len(self.udp_payload) > 0
