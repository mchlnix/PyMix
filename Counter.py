from constants import CTR_PREFIX_LEN
from util import i2b


class Counter:
    def __init__(self, start):
        self.current_value = start

    def count(self):
        self.current_value += 1

    def __bytes__(self):
        return i2b(self.current_value, CTR_PREFIX_LEN)

    def __int__(self):
        return self.current_value

    def __str__(self):
        return "0c" + str(self.current_value)
