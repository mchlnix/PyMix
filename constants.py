from sphinxmix.SphinxParams import SphinxParams

UDP_MTU = 65535

CHAN_ID_SIZE = 2

MIN_CHAN_ID = 1
MAX_CHAN_ID = 2**(8*CHAN_ID_SIZE)-1

MIN_PORT = 50000
MAX_PORT = 60000

REPLAY_WINDOW_SIZE = 10

CTR_PREFIX_LEN = 8
CTR_START_LEN = 8
CTR_MODE_PADDING = CTR_PREFIX_LEN

GCM_MAC_LEN = 16
NONCE_LEN = 16

SYM_KEY_LEN = 16

ASYM_OUTPUT_LEN = 256
ASYM_INPUT_LEN = 210
ASYM_PADDING_LEN = ASYM_OUTPUT_LEN - ASYM_INPUT_LEN

IPV4_LEN = 4
PORT_LEN = 2

RESERVED_LEN = 6

FRAGMENT_HEADER_LEN = CHAN_ID_SIZE + CTR_PREFIX_LEN + RESERVED_LEN

FLAG_LEN = 1

DATA_MSG_FLAG = int.to_bytes(1, 1, "big")
CHAN_INIT_MSG_FLAG = int.to_bytes(2, 1, "big")
CHAN_CONFIRM_MSG_FLAG = int.to_bytes(3, 1, "big")

# body_len cannot be less than twice the secret size k, because of the definition of beta in the paper

SPHINX_PARAMS = SphinxParams(header_len=115, body_len=44)
