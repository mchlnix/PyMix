from typing import List, Tuple

from petlib.bn import Bn
from petlib.ec import EcPt
from sphinxmix.SphinxParams import SphinxParams

params: SphinxParams

def group_expon(exponent: Bn) -> EcPt: ...
def gen_priv_key() -> Bn: ...
def get_pub_key(private_key: Bn) -> EcPt: ...

def gen_init_msg(pub_mix_keys: List[EcPt], channel_keys: List[bytes], payload: bytes) -> bytes: ...
def gen_blind(secret: EcPt) -> EcPt: ...
def process(priv_mix_key: Bn, message) -> Tuple[bytes, bytes, bytes]: ...