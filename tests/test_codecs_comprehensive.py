"""Comprehensive codec tests: VP8, H264, H265, AV1 unencrypted ranges and AV1 transform."""

import pytest

from sorrydave.media.codecs import (
    AV1_OBU_DROP_TYPES,
    H264_VCL_TYPES,
    VP8_HEADER_DELTA_LEN,
    VP8_HEADER_KEYFRAME_LEN,
    _av1_unencrypted_ranges,
    _h264_unencrypted_ranges,
    _h265_unencrypted_ranges,
    _leb128_decode,
    _leb128_encode_minimal,
    _vp8_unencrypted_ranges,
    get_unencrypted_ranges,
    transform_av1_frame_for_encrypt,
)
from sorrydave.types import UnencryptedRange


class TestGetUnencryptedRanges:
    """Top-level dispatcher tests."""

    def test_opus_full_encrypt(self):
        assert get_unencrypted_ranges(b"\x00" * 100, "OPUS") == []

    def test_vp9_full_encrypt(self):
        assert get_unencrypted_ranges(b"\x00" * 100, "VP9") == []

    def test_unknown_codec_full_encrypt(self):
        assert get_unencrypted_ranges(b"\x00" * 100, "UNKNOWN") == []

    def test_empty_string_codec(self):
        assert get_unencrypted_ranges(b"\x00", "") == []

    def test_case_insensitive(self):
        frame = b"\x01" + b"\x00" * 20
        ranges_lower = get_unencrypted_ranges(frame, "vp8")
        ranges_upper = get_unencrypted_ranges(frame, "VP8")
        assert len(ranges_lower) == len(ranges_upper)
        for a, b in zip(ranges_lower, ranges_upper):
            assert a.offset == b.offset
            assert a.length == b.length

    def test_h264_alias(self):
        frame = b"\x00\x00\x01\x67" + b"\xAA" * 10
        r1 = get_unencrypted_ranges(frame, "H264")
        r2 = get_unencrypted_ranges(frame, "H.264")
        assert r1 == r2

    def test_h265_aliases(self):
        frame = b"\x00\x00\x01\x80\x00" + b"\xAA" * 10
        r1 = get_unencrypted_ranges(frame, "H265")
        r2 = get_unencrypted_ranges(frame, "HEVC")
        r3 = get_unencrypted_ranges(frame, "H265/HEVC")
        assert r1 == r2 == r3


class TestVP8UnencryptedRanges:
    def test_empty_frame(self):
        assert _vp8_unencrypted_ranges(b"") == []

    def test_keyframe_p_bit_0(self):
        frame = b"\x00" + b"\xAA" * 20
        ranges = _vp8_unencrypted_ranges(frame)
        assert len(ranges) == 1
        assert ranges[0].offset == 0
        assert ranges[0].length == VP8_HEADER_KEYFRAME_LEN

    def test_delta_p_bit_1(self):
        frame = b"\x01" + b"\xAA" * 20
        ranges = _vp8_unencrypted_ranges(frame)
        assert len(ranges) == 1
        assert ranges[0].offset == 0
        assert ranges[0].length == VP8_HEADER_DELTA_LEN

    def test_keyframe_short_frame(self):
        frame = b"\x00\x01\x02"
        ranges = _vp8_unencrypted_ranges(frame)
        assert ranges[0].length == min(VP8_HEADER_KEYFRAME_LEN, 3)

    def test_single_byte_frame(self):
        frame = b"\x00"
        ranges = _vp8_unencrypted_ranges(frame)
        assert ranges[0].length == 1

    def test_p_bit_only_checks_lsb(self):
        frame = b"\xFE" + b"\xAA" * 20  # 0xFE: LSB=0 -> keyframe
        ranges = _vp8_unencrypted_ranges(frame)
        assert ranges[0].length == VP8_HEADER_KEYFRAME_LEN

        frame2 = b"\xFF" + b"\xAA" * 20  # 0xFF: LSB=1 -> delta
        ranges2 = _vp8_unencrypted_ranges(frame2)
        assert ranges2[0].length == VP8_HEADER_DELTA_LEN


class TestH264UnencryptedRanges:
    def test_empty_frame(self):
        assert _h264_unencrypted_ranges(b"") == []

    def test_non_vcl_nal_sps(self):
        """SPS (type 7) should have 1-byte header unencrypted."""
        frame = b"\x00\x00\x01\x67" + b"\xAA" * 10
        ranges = _h264_unencrypted_ranges(frame)
        assert len(ranges) == 1
        assert ranges[0].offset == 3
        assert ranges[0].length == 1

    def test_vcl_nal_fully_encrypted(self):
        """VCL types 1-5 produce no unencrypted ranges."""
        for nal_type in H264_VCL_TYPES:
            frame = b"\x00\x00\x01" + bytes([nal_type]) + b"\xAA" * 10
            ranges = _h264_unencrypted_ranges(frame)
            assert ranges == [], f"VCL type {nal_type} should have no unencrypted ranges"

    def test_4_byte_start_code(self):
        frame = b"\x00\x00\x00\x01\x67" + b"\xAA" * 10
        ranges = _h264_unencrypted_ranges(frame)
        assert len(ranges) == 1
        assert ranges[0].offset == 4
        assert ranges[0].length == 1

    def test_multiple_nals(self):
        frame = (
            b"\x00\x00\x01\x67" + b"\xAA" * 5
            + b"\x00\x00\x01\x68" + b"\xBB" * 5
            + b"\x00\x00\x01\x01" + b"\xCC" * 5
        )
        ranges = _h264_unencrypted_ranges(frame)
        types_found = []
        for r in ranges:
            types_found.append(frame[r.offset] & 0x1F)
        assert all(t not in H264_VCL_TYPES for t in types_found)

    def test_no_start_code(self):
        frame = b"\xAA\xBB\xCC\xDD"
        assert _h264_unencrypted_ranges(frame) == []


class TestH265UnencryptedRanges:
    def test_empty_frame(self):
        assert _h265_unencrypted_ranges(b"") == []

    def test_non_vcl_vps(self):
        """VPS: NAL type 32, should have 2-byte header unencrypted."""
        nal_byte = (32 << 1) & 0x7E  # type 32
        frame = b"\x00\x00\x01" + bytes([nal_byte, 0x00]) + b"\xAA" * 10
        ranges = _h265_unencrypted_ranges(frame)
        assert len(ranges) == 1
        assert ranges[0].length == 2

    def test_vcl_nal_no_ranges(self):
        """VCL types 0-31 should produce no unencrypted ranges."""
        for nal_type in [0, 1, 16, 31]:
            nal_byte = (nal_type << 1) & 0x7E
            frame = b"\x00\x00\x01" + bytes([nal_byte, 0x00]) + b"\xAA" * 10
            ranges = _h265_unencrypted_ranges(frame)
            assert ranges == [], f"VCL type {nal_type} should have no unencrypted ranges"

    def test_multiple_nals_mixed(self):
        vps_byte = (32 << 1) & 0x7E
        vcl_byte = (1 << 1) & 0x7E
        sps_byte = (33 << 1) & 0x7E
        frame = (
            b"\x00\x00\x01" + bytes([vps_byte, 0x00]) + b"\xAA" * 5
            + b"\x00\x00\x01" + bytes([vcl_byte, 0x00]) + b"\xBB" * 5
            + b"\x00\x00\x01" + bytes([sps_byte, 0x00]) + b"\xCC" * 5
        )
        ranges = _h265_unencrypted_ranges(frame)
        assert len(ranges) == 2


class TestLEB128Internal:
    """Tests for codecs-internal LEB128 helpers."""

    def test_encode_minimal_zero(self):
        assert _leb128_encode_minimal(0) == b"\x00"

    def test_encode_minimal_127(self):
        assert _leb128_encode_minimal(127) == b"\x7f"

    def test_encode_minimal_128(self):
        result = _leb128_encode_minimal(128)
        val, _ = _leb128_decode(result, 0)
        assert val == 128
        assert len(result) == 2

    def test_encode_minimal_negative_raises(self):
        with pytest.raises(ValueError):
            _leb128_encode_minimal(-1)

    @pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 1000, 0xFFFF, 0xFFFFFF])
    def test_encode_decode_roundtrip(self, value):
        encoded = _leb128_encode_minimal(value)
        decoded, off = _leb128_decode(encoded, 0)
        assert decoded == value
        assert off == len(encoded)

    def test_encode_minimal_no_padding(self):
        """Minimal encoding of 128 should be exactly 2 bytes, not padded."""
        enc = _leb128_encode_minimal(128)
        assert len(enc) == 2
        assert enc == bytes([0x80, 0x01])


class TestAV1UnencryptedRanges:
    def test_empty_frame(self):
        assert _av1_unencrypted_ranges(b"") == []

    def test_single_obu_header_only(self):
        obu_header = (1 << 3) | 0x02  # type=1 (SEQUENCE_HEADER), has_size=1
        frame = bytes([obu_header, 0x00])
        ranges = _av1_unencrypted_ranges(frame)
        assert len(ranges) == 1
        assert ranges[0].offset == 0

    def test_obu_with_extension(self):
        obu_header = (1 << 3) | 0x06  # type=1, has_ext=1, has_size=1
        ext_byte = 0x00
        frame = bytes([obu_header, ext_byte, 0x02, 0xAA, 0xBB])
        ranges = _av1_unencrypted_ranges(frame)
        assert len(ranges) == 1
        # header + ext + size = unencrypted
        assert ranges[0].length == 3

    def test_dropped_obu_types(self):
        """OBU types 2, 8, 15 should be skipped."""
        for drop_type in AV1_OBU_DROP_TYPES:
            obu_header = (drop_type << 3) | 0x02  # has_size=1
            frame = bytes([obu_header, 0x02, 0xAA, 0xBB])
            ranges = _av1_unencrypted_ranges(frame)
            assert ranges == [], f"OBU type {drop_type} should be dropped"

    def test_multiple_obus(self):
        obu1 = bytes([(1 << 3) | 0x02, 0x02, 0xAA, 0xBB])
        obu2 = bytes([(6 << 3) | 0x02, 0x01, 0xCC])
        frame = obu1 + obu2
        ranges = _av1_unencrypted_ranges(frame)
        assert len(ranges) == 2

    def test_last_obu_no_size(self):
        obu1 = bytes([(1 << 3) | 0x02, 0x02, 0xAA, 0xBB])
        obu2_header = (6 << 3) | 0x00  # no size field
        frame = obu1 + bytes([obu2_header, 0xCC, 0xDD])
        ranges = _av1_unencrypted_ranges(frame)
        assert len(ranges) == 2


class TestTransformAV1FrameForEncrypt:
    def test_empty_frame(self):
        assert transform_av1_frame_for_encrypt(b"") == b""

    def test_drops_temporal_delimiter(self):
        td_header = (2 << 3) | 0x02
        seq_header = (1 << 3) | 0x02
        frame = bytes([td_header, 0x00]) + bytes([seq_header, 0x02, 0xAA, 0xBB])
        result = transform_av1_frame_for_encrypt(frame)
        # Temporal delimiter should be dropped; only SEQ_HEADER remains
        assert result[0] >> 3 & 0x0F != 2

    def test_drops_padding_obu(self):
        pad_header = (15 << 3) | 0x02
        seq_header = (1 << 3) | 0x02
        frame = bytes([pad_header, 0x03, 0x00, 0x00, 0x00]) + bytes([seq_header, 0x01, 0xAA])
        result = transform_av1_frame_for_encrypt(frame)
        for i in range(len(result)):
            obu_type = (result[i] >> 3) & 0x0F
            if obu_type == 15:
                pytest.fail("Padding OBU should have been dropped")

    def test_drops_tile_list(self):
        tl_header = (8 << 3) | 0x02
        seq_header = (1 << 3) | 0x02
        frame = bytes([tl_header, 0x02, 0xAA, 0xBB]) + bytes([seq_header, 0x01, 0xCC])
        result = transform_av1_frame_for_encrypt(frame)
        for i in range(len(result)):
            obu_type = (result[i] >> 3) & 0x0F
            if obu_type == 8:
                pytest.fail("Tile list OBU should have been dropped")

    def test_last_obu_size_removed(self):
        """Last OBU should have obu_has_size_field cleared and size bytes removed."""
        obu1 = bytes([(1 << 3) | 0x02, 0x02, 0xAA, 0xBB])
        obu2 = bytes([(6 << 3) | 0x02, 0x02, 0xCC, 0xDD])
        frame = obu1 + obu2
        result = transform_av1_frame_for_encrypt(frame)
        last_header = result[-3]
        assert (last_header & 0x02) == 0, "Last OBU should have obu_has_size_field=0"

    def test_padded_leb128_reduced(self):
        """Padded LEB128 sizes in non-last OBUs should be reduced to minimal."""
        obu_header = (1 << 3) | 0x02
        padded_size = bytes([0x82, 0x00])  # padded LEB128 for 2
        obu1 = bytes([obu_header]) + padded_size + b"\xAA\xBB"
        obu2 = bytes([(6 << 3) | 0x02, 0x01, 0xCC])
        frame = obu1 + obu2
        result = transform_av1_frame_for_encrypt(frame)
        assert result[1] == 0x02

    def test_single_obu_frame(self):
        """Single OBU: should become the last (and only) OBU with size removed."""
        obu_header = (1 << 3) | 0x02
        frame = bytes([obu_header, 0x03, 0xAA, 0xBB, 0xCC])
        result = transform_av1_frame_for_encrypt(frame)
        assert (result[0] & 0x02) == 0
        assert result[1:] == b"\xAA\xBB\xCC"

    def test_preserves_payload(self):
        """Payload bytes should be preserved even after transformation."""
        obu1 = bytes([(1 << 3) | 0x02, 0x03, 0xAA, 0xBB, 0xCC])
        obu2 = bytes([(6 << 3) | 0x02, 0x02, 0xDD, 0xEE])
        frame = obu1 + obu2
        result = transform_av1_frame_for_encrypt(frame)
        assert b"\xAA\xBB\xCC" in result
        assert b"\xDD\xEE" in result

    def test_all_dropped_returns_original(self):
        """If all OBUs are dropped types, returns original frame."""
        td = bytes([(2 << 3) | 0x02, 0x00])
        pad = bytes([(15 << 3) | 0x02, 0x00])
        frame = td + pad
        result = transform_av1_frame_for_encrypt(frame)
        assert result == frame

    def test_extension_byte_preserved(self):
        """OBU extension byte should be preserved in output."""
        obu_header = (1 << 3) | 0x06  # has_ext=1, has_size=1
        ext_byte = 0x42
        frame = bytes([obu_header, ext_byte, 0x02, 0xAA, 0xBB])
        result = transform_av1_frame_for_encrypt(frame)
        assert ext_byte in result
