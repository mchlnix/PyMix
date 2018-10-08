from typing import Optional, Union


class _GMP:
    pass

_gmp: _GMP

class Integer:
    random: Optional[staticmethod]
    random_range: Optional[staticmethod]

    def __init__(self, value: int) -> None: ...
    def __int__(self) -> int: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def to_bytes(self, block_size: Optional[int]=0) -> bytes: ...
    @staticmethod
    def from_bytes(byte_string: bytes) -> Integer: ...
    def __eq__(self, term: object) -> bool: ...
    def __ne__(self, term: object) -> bool: ...
    def __lt__(self, term: Union[Integer, int]) -> bool: ...
    def __le__(self, term: Union[Integer, int]) -> bool: ...
    def __gt__(self, term: Union[Integer, int]) -> bool: ...
    def __ge__(self, term: Union[Integer, int]) -> bool: ...
    def __nonzero__(self) -> bool: ...
    def is_negative(self) -> bool: ...
    def __add__(self, term: Union[Integer, int]) -> Integer: ...
    def __sub__(self, term: Union[Integer, int]) -> Integer: ...
    def __mul__(self, term: Union[Integer, int]) -> Integer: ...
    def __floordiv__(self, divisor: Union[Integer, int]) -> Integer: ...
    def __mod__(self, divisor: Union[Integer, int]) -> Integer: ...
    def inplace_pow(self, exponent: int, modulus: Optional[Union[Integer, int]]=None) -> Integer: ...
    def __pow__(self, exponent: int, modulus: Optional[int]) -> Integer: ...
    def __abs__(self) -> Integer: ...
    def sqrt(self, modulus: Optional[int]) -> Integer: ...
    def __iadd__(self, term: Union[Integer, int]) -> Integer: ...
    def __isub__(self, term: Union[Integer, int]) -> Integer: ...
    def __imul__(self, term: Union[Integer, int]) -> Integer: ...
    def __imod__(self, divisor: Union[Integer, int]) -> Integer: ...
    def __and__(self, term: Union[Integer, int]) -> Integer: ...
    def __or__(self, term: Union[Integer, int]) -> Integer: ...
    def __rshift__(self, pos: Union[Integer, int]) -> Integer: ...
    def __irshift__(self, pos: Union[Integer, int]) -> Integer: ...
    def __lshift__(self, pos: Union[Integer, int]) -> Integer: ...
    def __ilshift__(self, pos: Union[Integer, int]) -> Integer: ...
    def get_bit(self, n: int) -> bool: ...
    def is_odd(self) -> bool: ...
    def is_even(self) -> bool: ...
    def size_in_bits(self) -> int: ...
    def size_in_bytes(self) -> int: ...
    def is_perfect_square(self) -> bool: ...
    def fail_if_divisible_by(self, small_prime: Union[Integer, int]) -> None: ...
    def multiply_accumulate(self, a: Union[Integer, int], b: Union[Integer, int]) -> Integer: ...
    def set(self, source: Union[Integer, int]) -> Integer: ...
    def inplace_inverse(self, modulus: Union[Integer, int]) -> Integer: ...
    def inverse(self, modulus: Union[Integer, int]) -> Integer: ...
    def gcd(self, term: Union[Integer, int]) -> Integer: ...
    def lcm(self, term: Union[Integer, int]) -> Integer: ...
    @staticmethod
    def jacobi_symbol(a: Union[Integer, int], n: Union[Integer, int]) -> Integer: ...
    def __del__(self) -> None: ...