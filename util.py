"""This module contains utility functions needed all over the PyMix project.
   They mostly focus on sequence and byte manipulation or mask internal
   builtin functionality, when it was not convenient enough to use."""
from math import ceil

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util import Counter

from constants import MAX_CHAN_ID, MIN_CHAN_ID, SYM_KEY_LEN, CTR_PREFIX_LEN, \
    GCM_MAC_LEN, CHAN_ID_SIZE, RESERVED_LEN, FRAGMENT_HEADER_LEN, NONCE_LEN

BYTE_ORDER = "big"


def b2i(int_in_bytes):
    """Takes a sequence of bytes and returns the integer they represent read in
    big endian order."""

    return int.from_bytes(int_in_bytes, byteorder=BYTE_ORDER)


def i2b(integer, length):
    """Takes an integer and returns length amount of bytes of the big endian
    representation of that integer. The return bytes might be padded with 0s
    or truncated to fit the length criteria."""

    return integer.to_bytes(length, byteorder=BYTE_ORDER)


def b2ip(ip_as_bytes):
    """Takes an integer representation of an IPv4 address and formats it into
    its 255.255.255.255 octet form."""

    return ".".join(str(int(byte)) for byte in ip_as_bytes)


def ip2b(ip_str):
    """Takes an IPv4 in the octet form of 255.255.255.255 and returns its
    integer representation by adding it up byte by byte."""

    return bytes([int(byte) for byte in ip_str.split('.')])


def parse_ip_port(ip_port):
    """Takes a string in the form of ipv4:port and returns a tuple suitable for
       use with sockets; (str, int)."""
    ip, port = ip_port.split(':')
    port = int(port)

    return ip, port


def padded(packet, blocksize):
    """Appends the byte for the character 'p' to the end of the packet, until
    it evenly divides by the given block size. Returns a string of bytes.
    The len() of the return value is always at least blocksize.
    """
    if blocksize < 1:
        raise ValueError("Block size can't be less than 1.")

    to_pad = 0

    # if empty, fill one complete block
    if not packet:
        to_pad = blocksize
    else:
        too_many = len(packet) % blocksize

        if too_many:
            to_pad = blocksize - too_many

    if to_pad:
        packet += get_random_bytes(to_pad)

    return packet


def prependlength(packet):
    """Prepends the length of the packet to the packet and returns it."""

    length = len(packet)
    lenbytes = bytes([length])

    if len(lenbytes) > 4:
        raise ValueError("Packet is longer than {} bytes.".format(2**32-1))

    return bytes(4-len(lenbytes))+lenbytes+packet


def items_from_file(filepath):
    """Reads the given file and returns a list of lines, without the new line
    character. All other whitespace within the lines is preserved."""

    with open(filepath, "r") as _file:
        items = _file.read().strip().split('\n')

    return items


def read_cfg_file(filepath):
    cfgs = dict()

    for item in items_from_file(filepath):
        key, value = item.strip().split('=')
        cfgs[key] = value

    return cfgs


def read_cfg_values(filepath):
    for item in items_from_file(filepath):
        value = item.strip().split('=')[1]
        yield value


def partitions(sequence, part_size):
    """Returns the number of chunks of the given size that could be filled by
    taking from sequence. If the sequence is empty 0 will be returned."""

    if part_size < 1:
        raise ValueError("Partition size can't be less than 1.")

    return int(ceil(len(sequence) / float(part_size)))


def partitioned(sequence, part_size):
    """Returns a list of chunks with the given length extracted from the given
    sequence. If the given sequence is empty, then an empty list will be
    returned. The last chunk may not be of given length, since there might not
    be enough elements to fill it completely."""

    parts = []
    for i in range(partitions(sequence, part_size)):
        index = i * part_size
        parts.append(sequence[index:index + part_size])

    return parts


def byte_len(integer):
    """Returns the number of bytes necessary to express the given integer
    value."""

    if integer < 0:
        raise ValueError("Can only do n>=0 at the moment.")

    if integer == 0:
        return 1

    return int(ceil(integer.bit_length() / 8.0))


def random_channel_id():
    return randint(MIN_CHAN_ID, MAX_CHAN_ID)


def cut(sequence, *cut_points):
    cur_place = 0

    for cut_point in cut_points:
        yield sequence[cur_place:cur_place + cut_point]
        cur_place += cut_point

    yield sequence[cur_place:]


# crypto
def gen_sym_key():
    return get_random_bytes(SYM_KEY_LEN)


def gen_ctr_prefix():
    return b2i(get_random_bytes(CTR_PREFIX_LEN))


def ctr_cipher(key, counter):
    # nbits = 8 bytes + prefix = 8 bytes
    ctr = Counter.new(nbits=64, prefix=i2b(counter, CTR_PREFIX_LEN))
    return AES.new(key, AES.MODE_CTR, counter=ctr)


def gcm_cipher(key, counter):
    # nbits = 8 bytes + prefix = 8 bytes
    return AES.new(key, AES.MODE_GCM,
                   nonce=i2b(counter, CTR_PREFIX_LEN) + bytes(NONCE_LEN - CTR_PREFIX_LEN),
                   mac_len=GCM_MAC_LEN)


def link_encrypt(key, plain_txt):
    chan_id, ctr_prefix, payload = cut(plain_txt, CHAN_ID_SIZE, CTR_PREFIX_LEN)

    link_ctr = gen_ctr_prefix()

    # use all 0s as link key, since they can not be exchanged yet
    cipher = gcm_cipher(key, link_ctr)

    # ctr encrypt the header with a random link counter prefix
    header, mac = cipher.encrypt_and_digest(
        chan_id + ctr_prefix + bytes(RESERVED_LEN))

    return i2b(link_ctr, CTR_PREFIX_LEN) + header + mac + payload


def link_decrypt(key, cipher_txt):
    link_ctr, header, mac, fragment = cut(cipher_txt, CTR_PREFIX_LEN,
                                          FRAGMENT_HEADER_LEN, GCM_MAC_LEN)

    cipher = gcm_cipher(key, b2i(link_ctr))

    plain_header = cipher.decrypt_and_verify(header, mac)

    chan_id, msg_ctr, reserved = cut(plain_header, CHAN_ID_SIZE, CTR_PREFIX_LEN)

    return b2i(chan_id), msg_ctr, fragment
