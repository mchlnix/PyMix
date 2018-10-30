from random import randint

from constants import CTR_PREFIX_LEN, SYM_KEY_LEN, ASYM_PADDING_LEN
from util import b2i, i2b
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
# Payload           306 - n*8 - 8 Bytes #
#########################################

# typical amount of mixes in the mix chain is 3

MIX_COUNT = 3

# channel init msg size
PACKET_SIZE = 256 + (MIX_COUNT - 1) * (ASYM_PADDING_LEN +
                                       SYM_KEY_LEN + 2 * CTR_PREFIX_LEN)

# one ctr prefix is in the header
FRAG_SIZE = PACKET_SIZE - (MIX_COUNT - 1) * CTR_PREFIX_LEN

ID_SIZE = 4

FRAG_COUNT_SIZE = 1
FRAG_INDEX_SIZE = FRAG_COUNT_SIZE  # have to stay equal size
PADDING_SIZE = 2

HEADER_SIZE = ID_SIZE + FRAG_COUNT_SIZE + FRAG_INDEX_SIZE + PADDING_SIZE

PAYLOAD_SIZE = FRAG_SIZE - HEADER_SIZE

MAX_FRAG_COUNT = 2**(FRAG_COUNT_SIZE*8)-1

HIGHEST_ID = 2**(ID_SIZE * 8) - 1
LOWEST_ID = 1


def make_fragments(packet):
    # how many fragments will be necessary
    frag_count = fragments(packet, PAYLOAD_SIZE)

    if frag_count > MAX_FRAG_COUNT:
        raise IndexError("Message too large.", frag_count,
                         "fragments necessary, limit is", MAX_FRAG_COUNT)

    # how many padding bytes will be necessary
    pad_len = 0

    if (len(packet) % PAYLOAD_SIZE) != 0:
        old_len = len(packet)
        packet = padded(packet, blocksize=PAYLOAD_SIZE)
        pad_len = len(packet) - old_len

    # get a random packet id
    packet_id = randint(LOWEST_ID, HIGHEST_ID)

    # assemble fragments
    frags = []
    for frag_index, fragment in enumerate(fragmented(packet, PAYLOAD_SIZE)):
        frag = []
        frag += i2b(packet_id, ID_SIZE)
        frag += i2b(frag_count, FRAG_COUNT_SIZE)
        frag += i2b(frag_index + 1, FRAG_INDEX_SIZE)
        frag += i2b(pad_len, PADDING_SIZE)
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

        msg_id, index = _read_int(raw_frag, index, ID_SIZE)

        if msg_id in self.packets:
            packet = self.packets[msg_id]
        else:
            packet = MixMessage(msg_id)

        packet.frag_count, index = _read_int(raw_frag, index, FRAG_COUNT_SIZE)

        frag_index, index = _read_int(raw_frag, index, FRAG_INDEX_SIZE)

        packet.pad_size, index = _read_int(raw_frag, index, PADDING_SIZE)

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
        self.payload_size = self.frag_count * PAYLOAD_SIZE - self.pad_size

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
