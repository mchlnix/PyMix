from typing import List, Tuple, Union

from petlib.bn import Bn
from petlib.ec import EcPt
from sphinxmix.SphinxParams import SphinxParams

params: SphinxParams

def group_expon(exponent: Bn) -> EcPt: ...
def gen_priv_key() -> Bn: ...
def get_pub_key(private_key: Bn) -> EcPt: ...

def gen_init_msg(pub_mix_keys: List[EcPt], message_counter: int, request_channel_keys: List[bytes], response_channel_keys: List[bytes], payload: bytes) -> bytes: ...
def gen_blind(secret: Union[EcPt,bytes]) -> Bn: ...
def process(priv_mix_key: Bn, message_counter: int, message: bytes) -> Tuple[bytes, bytes, bytes, bytes]: ...
def cut_init_message(message: bytes) -> Tuple[EcPt, bytes, bytes]: ...
