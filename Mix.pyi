from Types import AddressTuple

class Mix:
    cipher: Cipher
    incoming: socket
    next_addr: AddressTuple
    packet_store: MixMessageStore
    chan_table: TwoWayTable
    inchan2ip: Dict[int, AddressTuple]

    def get_outgoing_chan_id(self, in_chan_id: int) -> int: ...
    def handle_mix_fragment(self, payload: bytes, source: AddressTuple) -> int: ...
    def handle_response(self, payload: bytes) -> None: ...
    def run(self) -> None: ...

def random_channel_id() -> int: ...
def get_chan_id(payload: bytes) -> int: ...
def get_payload(packet: bytes) -> bytes: ...
