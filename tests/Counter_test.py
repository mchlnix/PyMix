from random import randint

from Counter import Counter
from constants import CTR_PREFIX_LEN
from util import i2b


def test_int():
    for _ in range(100):
        random_start = randint(0, 10000)

        counter = Counter(random_start)

        assert int(counter) == random_start


def test_bytes():
    for _ in range(100):
        random_start = randint(0, 10000)
        random_bytes = i2b(random_start, CTR_PREFIX_LEN)

        counter = Counter(random_start)

        assert bytes(counter) == random_bytes


def test_str():
    for _ in range(100):
        random_start = randint(0, 10000)
        random_str = "0c{}".format(random_start)

        counter = Counter(random_start)

        assert str(counter) == random_str


def test_next():
    counter = Counter(0)

    for i in range(0, 10000):
        assert i == int(counter)

        counter.count()
