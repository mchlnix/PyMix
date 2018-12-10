from Counter import Counter
from LinkEncryption import LinkEncryptor, LinkDecryptor
from constants import DATA_MSG_FLAG, CTR_PREFIX_LEN, CHAN_ID_SIZE, REPLAY_WINDOW_SIZE, CHANNEL_CTR_START
from util import get_random_bytes, i2b, gen_ctr_prefix, gen_sym_key

payload = get_random_bytes(200)
msg_type = DATA_MSG_FLAG
chan_id = 128
msg_ctr = bytes(Counter(CHANNEL_CTR_START))

link_key = gen_sym_key()


def test_link_encryption():
    encryptor = LinkEncryptor(link_key)
    decryptor = LinkDecryptor(link_key)

    encrypted = encryptor.encrypt(msg_type + i2b(chan_id, CHAN_ID_SIZE) + msg_ctr + payload)

    chan_id2, msg_ctr2, payload2, msg_type2 = decryptor.decrypt(encrypted)

    assert int(encryptor.counter) in decryptor.replay_detector
    assert chan_id == chan_id2
    assert msg_ctr == msg_ctr2
    assert payload == payload2
    assert msg_type == msg_type2


def test_replay_detection_already_seen():
    encryptor = LinkEncryptor(link_key)
    decryptor = LinkDecryptor(link_key)

    encrypted = encryptor.encrypt(msg_type + i2b(chan_id, CHAN_ID_SIZE) + msg_ctr + payload)

    _ = decryptor.decrypt(encrypted)

    try:
        decryptor.decrypt(encrypted)
    except Exception:
        assert True
        return

    assert False


def test_replay_detection_too_small():
    encryptor = LinkEncryptor(link_key)
    decryptor = LinkDecryptor(link_key)

    first_encrypted = encryptor.encrypt(msg_type + i2b(chan_id, CHAN_ID_SIZE) + msg_ctr + payload)
    first_link_counter = encryptor.counter

    for _ in range(REPLAY_WINDOW_SIZE + 1):
        encrypted = encryptor.encrypt(msg_type + i2b(chan_id, CHAN_ID_SIZE) + msg_ctr + payload)

        _ = decryptor.decrypt(encrypted)

    assert first_link_counter not in decryptor.replay_detector.replay_window

    try:
        decryptor.decrypt(first_encrypted)
    except Exception:
        assert True
        return

    assert False
