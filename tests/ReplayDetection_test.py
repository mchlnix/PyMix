from ReplayDetection import ReplayDetector, ReplayDetectedError
from constants import REPLAY_WINDOW_SIZE


def test_replay_detection():
    detector = ReplayDetector()

    replay_start = 20

    for i in range(1, replay_start + REPLAY_WINDOW_SIZE):
        detector.check_replay_window(i)

    try:
        detector.check_replay_window(1)
        assert False
    except ReplayDetectedError:
        pass

    try:
        detector.check_replay_window(replay_start)
        assert False
    except ReplayDetectedError:
        pass

    try:
        detector.check_replay_window(replay_start + REPLAY_WINDOW_SIZE // 2)
        assert False
    except ReplayDetectedError:
        pass

    try:
        detector.check_replay_window(replay_start + REPLAY_WINDOW_SIZE + 1)
        assert True
    except ReplayDetectedError:
        assert False
