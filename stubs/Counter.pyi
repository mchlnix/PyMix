class Counter:
    current_value: int

    def __init__(self, start: int) -> None: ...
    def count(self) -> int: ...
    def __bytes__(self) -> bytes: ...
    def __int__(self) -> int: ...
    def __str__(self) -> str: ...