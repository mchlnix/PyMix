#!/usr/bin/python3 -u
"""Some small unit tests for the util functions."""

from util import padded, partitions, partitioned

## padded
try:
    padded([1, 2, 3, 4], 0)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

try:
    padded([1, 2, 3, 4], -1)
    raise AssertionError("Expected ValueError")
except ValueError:
    pass

# lists
assert padded([], 2) == [ord('p'), ord('p')]
assert padded([1], 2) == [1, ord('p')]
assert padded([1, 1], 2) == [1, 1]

assert len(padded([], 2)) == 2
assert len(padded([1, 2, 3, 4], 16)) == 16
assert len(padded([1, 2, 3, 4], 3)) == 6

## partitions
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

## partitioned

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
