#!/usr/bin/python3 -u
"""Some small unit tests for the util functions."""
from constants import CHAN_ID_SIZE, DATA_MSG_FLAG, CTR_PREFIX_LEN
from util import padded, partitions, partitioned, cut, get_random_bytes, i2b, gen_ctr_prefix, link_decrypt, \
    link_encrypt, gen_sym_key

# padded
try:
    padded(bytes([1, 2, 3, 4]), 0)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

try:
    padded(bytes([1, 2, 3, 4]), -1)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

# lists
assert len(padded(bytes([]), 2)) == 2
assert len(padded(bytes([1, 2, 3, 4]), 16)) == 16
assert len(padded(bytes([1, 2, 3, 4]), 3)) == 6
assert len(padded(bytes([1, 2, 3, 4]), 4)) == 4

print("Success - padded")

# partitions
try:
    partitions([1, 2, 3, 4], 0)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

try:
    partitions([1, 2, 3, 4], -1)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

# strings
assert partitions("abcd", 1) == 4
assert partitions("abcd", 2) == 2
assert partitions("abcd", 3) == 2

assert partitions("_ä__", 2) == 2

assert partitions("", 1) == 0

# lists
assert partitions([1, 2, 3, 4], 1) == 4
assert partitions([1, 2, 3, 4], 2) == 2
assert partitions([1, 2, 3, 4], 3) == 2

assert partitions([], 1) == 0

print("Success - partitions")

# partitioned

try:
    partitioned([1, 2, 3, 4], 0)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

try:
    partitioned([1, 2, 3, 4], -1)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

assert partitioned([1, 2, 3, 4], 1) == [[1], [2], [3], [4]]
assert partitioned([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]
assert partitioned([1, 2, 3, 4], 3) == [[1, 2, 3], [4]]

assert partitioned([], 1) == []

print("Success - partitioned")

buffer = bytes(100)

part1, part2, part3 = cut(buffer, 50, 50)

assert part1 == bytes(50) == part2
assert len(part3) == 0

print("Success - cut")

payload = get_random_bytes(200)
msg_type = DATA_MSG_FLAG
chan_id = 128
msg_ctr = i2b(gen_ctr_prefix(), CTR_PREFIX_LEN)

link_ctr = gen_ctr_prefix()
link_key = gen_sym_key()

encrypted = link_encrypt(link_key, link_ctr, msg_type + i2b(chan_id, CHAN_ID_SIZE) + msg_ctr + payload)

link_ctr2, chan_id2, msg_ctr2, payload2, msg_type2 = link_decrypt(link_key, encrypted)

assert link_ctr == link_ctr2
assert chan_id == chan_id2
assert msg_ctr == msg_ctr2
assert payload == payload2
assert msg_type == msg_type2

print("Success - link encryption")
