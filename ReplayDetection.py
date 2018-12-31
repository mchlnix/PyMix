from constants import REPLAY_WINDOW_SIZE, LINK_CTR_START, CTR_PREFIX_LEN
from util import i2b


class ReplayDetectedError(Exception):
    pass


class ReplayDetector:
    def __init__(self, window_size=REPLAY_WINDOW_SIZE, start=LINK_CTR_START):
        self.replay_window = [start] * window_size

    def check_replay_window(self, ctr):
        if ctr in self:
            raise ReplayDetectedError(
                "Counter value {}/{} was too old or already seen.".format(ctr, i2b(ctr, CTR_PREFIX_LEN)))

        self.replay_window.append(ctr)

        # remove the smallest element
        self.replay_window.sort()
        self.replay_window.pop(0)

        return True

    def __contains__(self, ctr):
        return ctr in self.replay_window or ctr < self.replay_window[0]
