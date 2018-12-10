from typing import Tuple

from Counter import Counter
from ReplayDetection import ReplayDetector


class LinkEncryptor:
    key: bytes
    counter: Counter

    def __init__(self, link_key: bytes) -> None: ...
    def encrypt(self, plain_text: bytes) -> bytes: ...

class LinkDecryptor:
    key: bytes
    replay_detector: ReplayDetector

    def __init__(self, link_key: bytes) -> None:...
    def decrypt(self, cipher_text: bytes) -> Tuple[int, bytes, bytes, bytes]: ...
