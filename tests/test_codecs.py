import pytest
from pydave.media.codecs import get_unencrypted_ranges
from pydave.types import UnencryptedRange


def test_opus_full_encrypt():
    assert get_unencrypted_ranges(b"\x00\x01\x02", "OPUS") == []


def test_vp9_full_encrypt():
    assert get_unencrypted_ranges(b"anything", "VP9") == []


def test_vp8_keyframe():
    # P=0 -> 10 bytes unencrypted (RFC 7741: inverse key frame)
    frame = bytes([0b11111110]) + b"\x00" * 20
    ranges = get_unencrypted_ranges(frame, "VP8")
    assert ranges == [UnencryptedRange(offset=0, length=10)]


def test_vp8_delta():
    # P=1 -> 1 byte unencrypted
    frame = bytes([0b11111111]) + b"\x00" * 5
    ranges = get_unencrypted_ranges(frame, "VP8")
    assert ranges == [UnencryptedRange(offset=0, length=1)]


def test_unknown_codec():
    assert get_unencrypted_ranges(b"data", "H264") == []
