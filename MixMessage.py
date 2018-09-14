from random import randint

from util import padded, partitions as fragments, partitioned as fragmented
from util import b2i, i2b, i2ip, ip2i

#########################################
# MixMessage Fragment Format            #
#                                       #
# Packet ID                     4 Bytes #
# Number of fragments           1 Byte  #
# Number of this fragment       1 Byte  #
# Number of padding bytes       2 Bytes #
# Destination IP                4 Bytes #
# Destination Port              2 Bytes #
# Payload                      34 Bytes #
#########################################

FRAG_SIZE = 992

ID_SIZE = 4

FRAG_COUNT_SIZE = 1
FRAG_INDEX_SIZE = FRAG_COUNT_SIZE  # have to stay equal
PADDING_SIZE = 2

DEST_IP_SIZE = 4
DEST_PORT_SIZE = 2

HEADER_SIZE = ID_SIZE + FRAG_COUNT_SIZE + FRAG_INDEX_SIZE + PADDING_SIZE + \
              DEST_IP_SIZE + DEST_PORT_SIZE

PAYLOAD_SIZE = FRAG_SIZE - HEADER_SIZE

MAX_FRAG_COUNT = 2**(FRAG_COUNT_SIZE*8)-1

HIGHEST_ID = 2**(ID_SIZE * 8) - 1
LOWEST_ID = 1


def make_fragments(packet, dest_addr):
    # how many fragments will be necessary
    dest_ip, dest_port = dest_addr
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
        frag += i2b(ip2i(dest_ip), DEST_IP_SIZE)
        frag += i2b(dest_port, DEST_PORT_SIZE)
        frag += fragment

        frags.append(bytearray(frag))

    return frags


def _read_int(data, start, length):
    """Reads length bytes from start in data. Returns a tuple of the extracted
       bytes as an integer and the position where the reading stopped."""
    stop = start + length

    return b2i(data[start:stop]), stop


class MixMessageStore():
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

        ip, index = _read_int(raw_frag, index, DEST_IP_SIZE)
        port, index = _read_int(raw_frag, index, DEST_PORT_SIZE)

        packet.dest = (i2ip(ip), port)

        packet.add_fragment(frag_index, raw_frag[index:])

        self.packets[msg_id] = packet

        return self.packets[msg_id]

    def completed(self):
        return [packet for packet in self.packets.values() if packet.complete]

    def remove(self, msg_id):
        del self.packets[msg_id]

    def remove_completed(self):
        msg_ids = [packet.id for packet in self.completed()]

        for msg_id in msg_ids:
            self.remove(msg_id)


class MixMessage():
    def __init__(self, msg_id):
        self.fragments = dict()
        self.id = msg_id
        self.frag_count = 0
        self.dest = ("-1.-1.-1.-1", -1)
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
        if self.complete:
            payload = bytes()
            for i in range(1, self.frag_count+1):
                payload += self.fragments[i]

            if self.pad_size:
                return payload[0: -self.pad_size]
            else:
                return payload

        return ""

    def __str__(self):
        ret = ""
        ret += "MixMessage:  {}\n".format(self.id)
        ret += "Fragments:   {}/{}\n".format(len(self.fragments),
                                             self.frag_count)
        ret += "Size:        {}\n".format(self.payload_size)
        ret += "Padding:     {}\n".format(self.pad_size)
        ret += "Destination: {}:{}\n".format(*self.dest)

        if self.complete:
            payload = ":".join("{:02x}".format(b) for b in self.payload[0:16])
            ret += "Payload:     {}...\n".format(payload)

        return ret
