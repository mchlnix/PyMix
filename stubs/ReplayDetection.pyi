from typing import Optional, List


class ReplayDetectedError(Exception):
    pass


class ReplayDetector:
    replay_window: List[int]
    def __init__(self, window_size: Optional[int]=..., start: Optional[int]=...): ...

    def check_replay_window(self, ctr: int) -> bool: ...
    def __contains__(self, ctr: int) -> bool: ...
