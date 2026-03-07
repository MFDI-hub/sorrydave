import pytest
from sorrydave.media.codecs import get_unencrypted_ranges
from sorrydave.types import UnencryptedRange


def test_opus_full_encrypt():
    """OPUS codec returns no unencrypted ranges (full frame encrypted)."""
    assert get_unencrypted_ranges(b"\x00\x01\x02", "OPUS") == []


def test_vp9_full_encrypt():
    """VP9 codec returns no unencrypted ranges (full frame encrypted)."""
    assert get_unencrypted_ranges(b"anything", "VP9") == []


def test_vp8_keyframe():
    """
    VP8 with P=0 (key frame) leaves 10 bytes unencrypted (RFC 7741).
    """
    # P=0 -> 10 bytes unencrypted (RFC 7741: inverse key frame)
    frame = bytes([0b11111110]) + b"\x00" * 20
    ranges = get_unencrypted_ranges(frame, "VP8")
    assert ranges == [UnencryptedRange(offset=0, length=10)]


def test_vp8_delta():
    """
    VP8 with P=1 (delta frame) leaves 1 byte unencrypted.
    """
    # P=1 -> 1 byte unencrypted
    frame = bytes([0b11111111]) + b"\x00" * 5
    ranges = get_unencrypted_ranges(frame, "VP8")
    assert ranges == [UnencryptedRange(offset=0, length=1)]


def test_unknown_codec():
    """Unknown codec returns empty ranges (full encrypt)."""
    assert get_unencrypted_ranges(b"data", "FOO") == []


def test_h264_non_vcl_one_byte_header():
    """
    H264 non-VCL NAL (e.g. type 7 SPS) gets 1-byte header unencrypted.
    """
    # Annex B: 0x00 0x00 0x01 start code, then NAL type 7 (SPS) = non-VCL -> 1 byte unencrypted
    frame = b"\x00\x00\x01\x07\x00\x00\x00\x01\x01\x02\x03"  # NAL 7, then NAL 1 (VCL)
    ranges = get_unencrypted_ranges(frame, "H264")
    assert UnencryptedRange(offset=3, length=1) in ranges  # byte at 3 is NAL 7 header
    # NAL type 1 is VCL so no unencrypted range for second NAL
    assert len(ranges) == 1


def test_h264_vcl_fully_encrypted():
    """
    H264 VCL NAL (type 1) is fully encrypted; no unencrypted ranges.
    """
    # Single VCL NAL (type 1)
    frame = b"\x00\x00\x01\x01\xaa\xbb\xcc"
    ranges = get_unencrypted_ranges(frame, "H264")
    assert ranges == []


def test_h265_non_vcl_two_byte_header():
    """
    H265 non-VCL NAL gets 2-byte header unencrypted.
    """
    # NAL type 33 (SPS) = non-VCL, 2-byte header; first NAL has at least 2 bytes
    frame = b"\x00\x00\x01\x42\x00\xaa\x00\x00\x00\x01\x40\x01"
    ranges = get_unencrypted_ranges(frame, "H265")
    assert len(ranges) >= 1
    assert ranges[0].offset == 3 and ranges[0].length == 2


def test_av1_obu_header_only():
    """
    AV1 OBU with only 1-byte header (no extension/size) leaves 1 byte unencrypted.
    """
    # Minimal OBU: 1 byte header (type 1 = sequence_header), no extension, no size (last OBU)
    # obu_has_size_field = 0, obu_has_extension = 0 -> type 1 << 3 = 8
    frame = bytes([(1 << 3) | 0]) + b"payload"
    ranges = get_unencrypted_ranges(frame, "AV1")
    assert ranges == [UnencryptedRange(offset=0, length=1)]


def test_av1_obu_with_size():
    """
    AV1 OBU with size field: header + LEB128 size bytes are unencrypted.
    """
    # OBU with size: header 0x0a (type=1, has_size=1), LEB128 size 3, payload 3 bytes
    # 0x0a = 10 = 0b1010 -> type 1, has_extension 0, has_size 1
    frame = bytes([(1 << 3) | 2]) + bytes([3]) + b"xyz"
    ranges = get_unencrypted_ranges(frame, "AV1")
    assert ranges[0].offset == 0
    assert ranges[0].length == 2  # 1 header + 1 LEB128
