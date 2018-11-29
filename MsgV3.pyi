from typing import List

from petlib.ec import EcPt
from sphinxmix.SphinxParams import SphinxParams


class MsgFactory:
    pub_mix_keys: List[EcPt]
    params: SphinxParams

    def __init__(self, pub_mix_keys: List[EcPt], params: SphinxParams) -> None: ...
    def gen_init_msg(self, channel_keys: List[bytes], payload: bytes) -> bytes: ...
    def gen_blind(self, group_elem: EcPt, secret: EcPt) -> EcPt: ...