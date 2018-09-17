from Types import AddressTuple

def random_channel_id() -> int: ...
def get_chan_id(payload: bytes) -> int: ...
def get_payload(packet: bytes) -> bytes: ...
def get_outgoing_chan_id(in_chan_id: int) -> int: ...
def handle_mix_fragment(payload: bytes, source: AddressTuple) -> int: ...
def handle_response(payload: bytes) -> None: ...