#!/usr/bin/python3

from MixMessage import FragmentGenerator, padding_length_to_bytes, how_many_padding_bytes_necessary, FRAG_FLAG_SIZE, \
    FRAG_ID_SIZE, bytes_to_padding_length, make_dummy_data_fragment, make_dummy_init_fragment, parse_fragment
from constants import FRAG_PAYLOAD_SIZE
from util import i2b, b2i, cut, get_random_bytes

paddings = {0: bytes(0),
            1: i2b(0b1000_0000, 1),
            2: i2b(0b1000_0001, 1),
            127: i2b(0b1111_1110, 1),
            128: i2b(0b1111_1111, 1),
            129: i2b(0b0000_0000_1111_1111, 2),
            130: i2b(0b0000_0001_1000_0000, 2),
            256: i2b(0b0000_0001_1111_1110, 2),
            257: i2b(0b0000_0001_1111_1111, 2),
            258: i2b(0b0000_0010_1000_0000, 2),
            271: i2b(0b0000_0010_1000_1101, 2),
            272: i2b(0b0000_0010_1000_1110, 2),
            }


def test_how_many_padding_bytes():
    assert 1 == how_many_padding_bytes_necessary(1) == how_many_padding_bytes_necessary(2**7)
    assert 2 == how_many_padding_bytes_necessary(2**7+1) == how_many_padding_bytes_necessary(2**14)
    assert 3 == how_many_padding_bytes_necessary(2**14+1) == how_many_padding_bytes_necessary(2**21)


def test_padding_length_to_bytes():
    try:
        for padding_length in paddings:
            padding_bytes, _ = padding_length_to_bytes(padding_length)
            print("\rPadding", padding_length, "was", padding_bytes, end="")
            assert paddings[padding_length] == padding_bytes
    except AssertionError as ae:
        print()
        raise ae


def test_bytes_to_padding_length():
    for padding, padding_bytes in paddings.items():
        if padding <= 0:
            continue

        padding_read, bytes_read = bytes_to_padding_length(padding_bytes)

        assert len(padding_bytes) == bytes_read
        assert padding == padding_read + bytes_read


def test_get_data_fragment():
    udp_payload = get_random_bytes(FRAG_PAYLOAD_SIZE)

    f = FragmentGenerator(udp_payload)

    fragment = f.get_data_fragment()

    _, frag_byte, payload = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE)

    assert b2i(frag_byte) & FragmentGenerator.LAST_FRAG_FLAG
    assert b2i(frag_byte) == 0b0100_0000
    assert payload[0:FRAG_PAYLOAD_SIZE] == udp_payload
    assert len(fragment) == FRAG_PAYLOAD_SIZE + FRAG_ID_SIZE + FRAG_FLAG_SIZE


def test_get_data_fragment_with_padding():
    udp_payload = get_random_bytes(FRAG_PAYLOAD_SIZE - 1)

    f = FragmentGenerator(udp_payload)

    fragment = f.get_data_fragment()

    _, frag_byte, _, payload = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE, 1)

    assert b2i(frag_byte) & FragmentGenerator.LAST_FRAG_FLAG
    assert b2i(frag_byte) & FragmentGenerator.PADDING_FLAG
    assert b2i(frag_byte) == 0b1100_0000
    assert payload[0:FRAG_PAYLOAD_SIZE - 1] == udp_payload
    assert len(fragment) == FRAG_PAYLOAD_SIZE + FRAG_ID_SIZE + FRAG_FLAG_SIZE

    udp_payload = get_random_bytes(1)

    f = FragmentGenerator(udp_payload)

    fragment = f.get_data_fragment()

    _, frag_byte, _, payload = cut(fragment, FRAG_ID_SIZE, FRAG_FLAG_SIZE, 2)

    assert b2i(frag_byte) & FragmentGenerator.LAST_FRAG_FLAG
    assert b2i(frag_byte) & FragmentGenerator.PADDING_FLAG
    assert b2i(frag_byte) == 0b1100_0000
    assert payload[0:1] == udp_payload
    assert len(fragment) == FRAG_PAYLOAD_SIZE + FRAG_ID_SIZE + FRAG_FLAG_SIZE


def test_parse_fragment():
    udp_payload = get_random_bytes(120)

    f = FragmentGenerator(udp_payload)

    fragment = f.get_data_fragment()

    msg_id, is_last, fragment_id, payload = parse_fragment(fragment)

    assert msg_id == f.message_id
    assert is_last
    assert fragment_id == 0
    assert udp_payload == payload


def test_get_data_fragment_2_fragments():
    udp_payload = get_random_bytes(400)
    fragmented_payload = bytes()

    f = FragmentGenerator(udp_payload)

    fragment = f.get_data_fragment()

    msg_id, is_last, fragment_id, payload = parse_fragment(fragment)

    fragmented_payload += payload

    assert msg_id == f.message_id
    assert not is_last
    assert fragment_id == 0

    fragment = f.get_data_fragment()

    msg_id, is_last, fragment_id, payload = parse_fragment(fragment)

    fragmented_payload += payload

    assert msg_id == f.message_id
    assert is_last
    assert fragment_id == 1
    assert udp_payload == fragmented_payload


def test_get_init_fragment():
    udp_payload = get_random_bytes(120)

    f = FragmentGenerator(udp_payload)

    fragment = f.get_init_fragment()

    msg_id, is_last, fragment_id, payload = parse_fragment(fragment)

    assert msg_id == f.message_id
    assert is_last
    assert fragment_id == 0
    assert udp_payload == payload


def test_make_dummy_data_fragment():
    fragment = make_dummy_data_fragment()

    msg_id, is_last, fragment_id, payload = parse_fragment(fragment)

    assert msg_id == 0
    assert fragment_id == 0
    assert is_last
    assert payload == bytes()


def test_make_dummy_init_fragment():
    fragment = make_dummy_init_fragment()

    msg_id, is_last, fragment_id, payload = parse_fragment(fragment)

    assert msg_id == 0
    assert fragment_id == 0
    assert is_last
    assert payload == bytes()
