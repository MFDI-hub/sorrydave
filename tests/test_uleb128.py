import pytest
from pydave.crypto.cipher import uleb128_encode, uleb128_decode


def test_uleb128_roundtrip():
    """ULEB128 encode/decode roundtrip for various values."""
    for value in [0, 1, 127, 128, 255, 12345, 0x3FFF, 0x7F]:
        encoded = uleb128_encode(value)
        decoded, offset = uleb128_decode(encoded, 0)
        assert decoded == value
        assert offset == len(encoded)


def test_uleb128_decode_offset():
    """uleb128_decode with offset decodes consecutive values correctly."""
    data = uleb128_encode(100) + uleb128_encode(200)
    v1, off1 = uleb128_decode(data, 0)
    v2, off2 = uleb128_decode(data, off1)
    assert v1 == 100
    assert v2 == 200
    assert off2 == len(data)
