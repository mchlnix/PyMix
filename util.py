"""This module contains utility functions needed all over the PyMix project.
   They mostly focus on sequence and byte manipulation or mask internal
   builtin functionality, when it was not convenient enough to use."""
from math import ceil

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


def i2ip(integer):
    """Takes an integer representation of an IPv4 address and formats it into
    its 255.255.255.255 octet form."""

    _bytes = i2b(integer, 4)
    return ".".join(str(byte) for byte in _bytes)

def ip2i(ip_str):
    """Takes an IPv4 in the octet form of 255.255.255.255 and returns its
    integer representation by adding it up byte by byte."""

    _bytes = ip_str.split('.')

    ret_int = int(_bytes[0]) << 24
    ret_int += int(_bytes[1]) << 16
    ret_int += int(_bytes[2]) << 8
    ret_int += int(_bytes[3])

    return ret_int

def parse_ip_port(ip_port):
    """Takes a string in the form of ipv4:port and returns a tuple suitable for
       use with sockets; (str, int)."""
    ip, port = ip_port.split(':')
    port = int(port)

    return (ip, port)

def padded(packet, blocksize):
    """Appends the byte for the character 'p' to the end of the packet, until
    it evenly divides by the given block size. Returns a string of bytes.
    The len() of the return value is always at least blocksize.
    """
    if blocksize < 1:
        raise ValueError("Block size can't be less than 1.")

    to_pad = 0

    if len(packet) == 0:
        to_pad = blocksize
    else:
        too_many = len(packet) % blocksize

        if too_many:
            to_pad = blocksize - too_many

    packet += ('p'*to_pad).encode("ascii")

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
