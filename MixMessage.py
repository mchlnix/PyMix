import math
from random import randint

from constants import CTR_PREFIX_LEN, MIX_COUNT, FRAG_PAYLOAD_SIZE, INIT_OVERHEAD, DATA_OVERHEAD
from util import b2i, i2b, get_random_bytes, cut
from util import padded, partitions as fragments, partitioned as fragmented

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

FRAG_HEADER_SIZE = FRAG_ID_SIZE + FRAG_COUNT_SIZE + FRAG_INDEX_SIZE + FRAG_PADDING_SIZE

MAX_FRAG_COUNT = 2 ** (FRAG_COUNT_SIZE * 8) - 1

HIGHEST_ID = 2 ** (FRAG_ID_SIZE * 8) - 1
LOWEST_ID = 1

DATA_PACKET_SIZE = (MIX_COUNT-1) * CTR_PREFIX_LEN + FRAG_HEADER_SIZE + FRAG_PAYLOAD_SIZE


def make_fragments(packet):
    # how many fragments will be necessary
    frag_count = fragments(packet, FRAG_PAYLOAD_SIZE)

    if frag_count > MAX_FRAG_COUNT:
        raise IndexError("Message too large.", frag_count,
                         "fragments necessary, limit is", MAX_FRAG_COUNT)

    # how many padding bytes will be necessary
    pad_len = 0

    if (len(packet) % FRAG_PAYLOAD_SIZE) != 0:
        old_len = len(packet)
        packet = padded(packet, blocksize=FRAG_PAYLOAD_SIZE)
        pad_len = len(packet) - old_len

    # get a random packet id
    packet_id = randint(LOWEST_ID, HIGHEST_ID)

    # assemble fragments
    frags = []
    for frag_index, fragment in enumerate(fragmented(packet, FRAG_PAYLOAD_SIZE)):
        frag = []
        frag += i2b(packet_id, FRAG_ID_SIZE)
        frag += i2b(frag_count, FRAG_COUNT_SIZE)
        frag += i2b(frag_index + 1, FRAG_INDEX_SIZE)
        frag += i2b(pad_len, FRAG_PADDING_SIZE)
        frag += fragment

        frags.append(bytearray(frag))

    return frags


def _read_int(data, start, length):
    """Reads length bytes from start in data. Returns a tuple of the extracted
       bytes as an integer and the position where the reading stopped."""
    stop = start + length

    return b2i(data[start:stop]), stop


class MixMessageStore:
    def __init__(self):
        self.packets = dict()

    def parse_fragment(self, raw_frag):
        index = 0

        msg_id, index = _read_int(raw_frag, index, FRAG_ID_SIZE)

        if msg_id in self.packets:
            packet = self.packets[msg_id]
        else:
            packet = MixMessage(msg_id)

        packet.frag_count, index = _read_int(raw_frag, index, FRAG_COUNT_SIZE)

        frag_index, index = _read_int(raw_frag, index, FRAG_INDEX_SIZE)

        packet.pad_size, index = _read_int(raw_frag, index, FRAG_PADDING_SIZE)

        packet.add_fragment(frag_index, raw_frag[index:])

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
        self.pad_size = 0
        self.payload_size = 0

    def add_fragment(self, frag_index, payload):
        if frag_index in self.fragments:
            return

        self.fragments[frag_index] = payload
        self.payload_size = self.frag_count * FRAG_PAYLOAD_SIZE - self.pad_size

    @property
    def complete(self):
        return len(self.fragments) == self.frag_count

    @property
    def payload(self):
        payload = bytes()
        if self.complete:
            for i in range(1, self.frag_count+1):
                payload += self.fragments[i]

            if self.pad_size:
                return payload[0: -self.pad_size]

        return payload

    def __str__(self):
        ret = ""
        ret += "MixMessage:  {}\n".format(self.id)
        ret += "Fragments:   {}/{}\n".format(len(self.fragments),
                                             self.frag_count)
        ret += "Size:        {}\n".format(self.payload_size)
        ret += "Padding:     {}\n".format(self.pad_size)

        if self.complete:
            payload = ":".join("{:02x}".format(b) for b in self.payload[0:16])
            ret += "Payload:     {}...\n".format(payload)

        return ret


FRAG_FLAG_SIZE = 1
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
    packet_id, frag_byte, rest = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE)

    print("Packet id is:", b2i(packet_id))

    if b2i(frag_byte) & FragmentGenerator.LAST_FRAG_FLAG:
        print("Fragment is the last fragment.")

    payload_len = len(rest)

    if b2i(frag_byte) & FragmentGenerator.PADDING_FLAG:
        padding_len, padding_bytes = bytes_to_padding_length(rest)

        print("Fragment has a padding length field of size", padding_bytes, "bytes.")

        print("Fragment has", padding_len, "padding bytes.")

        payload_len -= (padding_len + padding_bytes)

    print("Fragment has", payload_len, " payload bytes.")


class FragmentGenerator:
    data_payload_limit = FRAG_PAYLOAD_SIZE
    init_payload_limit = FRAG_PAYLOAD_SIZE - (INIT_OVERHEAD - DATA_OVERHEAD)

    PADDING_FLAG = 0x80
    LAST_FRAG_FLAG = 0x40

    PADDING_BITMASK = 0x7F

    def __init__(self, udp_payload):
        self.udp_payload = udp_payload
        self.packet_id = randint(LOWEST_ID, HIGHEST_ID)
        self.current_fragment = 0

    def get_init_fragment(self):
        return self._build_fragment(FragmentGenerator.init_payload_limit)

    def get_data_fragment(self):
        return self._build_fragment(FragmentGenerator.data_payload_limit)

    def _build_fragment(self, payload_limit):
        if self.current_fragment > 0b0011_1111:
            raise ValueError("Too many fragments needed for this payload.")

        if len(self.udp_payload) == 0:
            raise ValueError("No more fragments left to generate.")

        frag_byte = self.current_fragment

        self.current_fragment += 1

        if len(self.udp_payload) <= payload_limit:
            frag_byte |= FragmentGenerator.LAST_FRAG_FLAG

        if len(self.udp_payload) < payload_limit:
            frag_byte |= FragmentGenerator.PADDING_FLAG

            padding_bytes, padding_len = padding_length_to_bytes(payload_limit - len(self.udp_payload))
        else:
            padding_len = 0
            padding_bytes = bytes()

        fragment = i2b(self.packet_id, FRAG_ID_SIZE) + i2b(frag_byte, FRAG_FLAG_SIZE)

        fragment += padding_bytes

        fragment += self.udp_payload[:payload_limit] + get_random_bytes(padding_len)

        self.udp_payload = self.udp_payload[payload_limit:]

        return fragment

    def __bool__(self):
        return len(self.udp_payload) > 0
