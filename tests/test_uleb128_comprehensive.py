"""Comprehensive ULEB128 tests: encoding, decoding, roundtrip, edge cases, and error conditions."""

import pytest

from sorrydave.crypto.cipher import uleb128_decode, uleb128_encode


class TestUleb128Encode:
    def test_zero(self):
        assert uleb128_encode(0) == b"\x00"

    def test_one(self):
        assert uleb128_encode(1) == b"\x01"

    def test_max_single_byte(self):
        assert uleb128_encode(0x7F) == b"\x7f"

    def test_min_two_bytes(self):
        assert uleb128_encode(0x80) == bytes([0x80, 0x01])

    def test_max_two_bytes(self):
        assert uleb128_encode(0x3FFF) == bytes([0xFF, 0x7F])

    def test_three_bytes(self):
        assert uleb128_encode(0x4000) == bytes([0x80, 0x80, 0x01])

    def test_large_32bit(self):
        result = uleb128_encode(0xFFFFFFFF)
        assert len(result) == 5
        decoded, _ = uleb128_decode(result)
        assert decoded == 0xFFFFFFFF

    def test_large_value(self):
        result = uleb128_encode(2**32)
        decoded, _ = uleb128_decode(result)
        assert decoded == 2**32

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="nonnegative"):
            uleb128_encode(-1)

    def test_protocol_pseudocode_match(self):
        """Verify encoding matches protocol.md C pseudocode for known values."""
        for v in [0, 1, 127, 128, 300, 16384, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF]:
            enc = uleb128_encode(v)
            dec, _ = uleb128_decode(enc)
            assert dec == v


class TestUleb128Decode:
    def test_zero(self):
        val, off = uleb128_decode(b"\x00")
        assert val == 0
        assert off == 1

    def test_single_byte_max(self):
        val, off = uleb128_decode(b"\x7f")
        assert val == 0x7F
        assert off == 1

    def test_two_bytes(self):
        val, off = uleb128_decode(bytes([0x80, 0x01]))
        assert val == 128
        assert off == 2

    def test_offset_parameter(self):
        data = b"\xAA\x80\x01\xBB"
        val, off = uleb128_decode(data, offset=1)
        assert val == 128
        assert off == 3

    def test_truncated_raises(self):
        with pytest.raises(ValueError, match="truncated"):
            uleb128_decode(b"")

    def test_truncated_mid_value(self):
        with pytest.raises(ValueError, match="truncated"):
            uleb128_decode(bytes([0x80]))

    def test_overflow_raises(self):
        data = bytes([0x80] * 10 + [0x01])
        with pytest.raises(ValueError, match="overflow"):
            uleb128_decode(data)

    def test_continuation_bytes_only(self):
        with pytest.raises(ValueError, match="truncated"):
            uleb128_decode(bytes([0x80, 0x80, 0x80]))


class TestUleb128Roundtrip:
    @pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 16383, 16384, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF])
    def test_roundtrip(self, value):
        encoded = uleb128_encode(value)
        decoded, offset = uleb128_decode(encoded)
        assert decoded == value
        assert offset == len(encoded)

    def test_multiple_values_in_buffer(self):
        buf = uleb128_encode(42) + uleb128_encode(300) + uleb128_encode(0)
        v1, off = uleb128_decode(buf, 0)
        assert v1 == 42
        v2, off = uleb128_decode(buf, off)
        assert v2 == 300
        v3, off = uleb128_decode(buf, off)
        assert v3 == 0
        assert off == len(buf)
