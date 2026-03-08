"""Comprehensive frame encryptor/decryptor and protocol_frame_check tests."""

import pytest

from sorrydave.crypto.cipher import DAVE_MAGIC, uleb128_encode
from sorrydave.crypto.ratchet import KeyRatchet
from sorrydave.exceptions import DecryptionError
from sorrydave.media.transform import (
    MIN_SUPPLEMENTAL,
    SILENCE_PACKET,
    FrameDecryptor,
    FrameEncryptor,
    _apply_h26x_start_code_expansion,
    _build_supplemental_footer,
    _contains_h26x_start_code,
    _parse_supplemental_from_tail,
    _replace_3byte_start_with_4byte,
    protocol_frame_check,
)
from sorrydave.types import UnencryptedRange


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ratchet(secret: bytes = b"\x01" * 16, **kw) -> KeyRatchet:
    return KeyRatchet(secret, **kw)


def encrypt_frame(
    frame: bytes,
    codec: str = "OPUS",
    secret: bytes = b"\x01" * 16,
    **enc_kw,
) -> tuple[bytes, FrameEncryptor]:
    ratchet = make_ratchet(secret)
    enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet, **enc_kw)
    return enc.encrypt(frame, codec), enc


# ---------------------------------------------------------------------------
# H26x Start-Code Helpers
# ---------------------------------------------------------------------------

class TestReplaceStartCode:
    def test_no_start_code(self):
        data = b"\x01\x02\x03\x04"
        assert _replace_3byte_start_with_4byte(data) == data

    def test_single_start_code(self):
        data = b"\x00\x00\x01\xAA"
        result = _replace_3byte_start_with_4byte(data)
        assert result == b"\x00\x00\x00\x01\xAA"

    def test_multiple_start_codes(self):
        data = b"\x00\x00\x01\xAA\x00\x00\x01\xBB"
        result = _replace_3byte_start_with_4byte(data)
        assert result.count(b"\x00\x00\x00\x01") == 2

    def test_empty(self):
        assert _replace_3byte_start_with_4byte(b"") == b""


class TestContainsStartCode:
    def test_contains_3byte(self):
        assert _contains_h26x_start_code(b"\x00\x00\x01") is True

    def test_contains_4byte(self):
        assert _contains_h26x_start_code(b"\x00\x00\x00\x01") is True

    def test_no_start_code(self):
        assert _contains_h26x_start_code(b"\x00\x00\x02") is False

    def test_empty(self):
        assert _contains_h26x_start_code(b"") is False

    def test_too_short(self):
        assert _contains_h26x_start_code(b"\x00\x00") is False


class TestApplyH26xStartCodeExpansion:
    def test_empty_ranges(self):
        frame, ranges = _apply_h26x_start_code_expansion(b"\xAA\xBB", [])
        assert frame == b"\xAA\xBB"
        assert ranges == []

    def test_expansion_updates_offset(self):
        frame = b"\x00\x00\x01\xAA\xBB"
        ranges = [UnencryptedRange(offset=0, length=3)]
        new_frame, new_ranges = _apply_h26x_start_code_expansion(frame, ranges)
        assert new_ranges[0].length == 4
        assert new_frame[:4] == b"\x00\x00\x00\x01"


# ---------------------------------------------------------------------------
# Supplemental Footer
# ---------------------------------------------------------------------------

class TestBuildSupplementalFooter:
    def test_basic(self):
        tag = b"\xAA" * 8
        body = _build_supplemental_footer(tag, 0, [])
        assert body[:8] == tag
        assert body[8:] == uleb128_encode(0)

    def test_with_ranges(self):
        tag = b"\xBB" * 8
        ranges = [UnencryptedRange(offset=0, length=5)]
        body = _build_supplemental_footer(tag, 42, ranges)
        assert body[:8] == tag


class TestParseSupplementalFromTail:
    def _build_protocol_frame(self, interleaved: bytes, tag: bytes, nonce: int,
                               ranges: list[UnencryptedRange]) -> bytes:
        body = _build_supplemental_footer(tag, nonce, ranges)
        suppl_size = len(body) + 1 + 2
        return interleaved + body + bytes([suppl_size]) + DAVE_MAGIC

    def test_roundtrip(self):
        frame = self._build_protocol_frame(b"\xCC" * 10, b"\xDD" * 8, 42, [])
        suppl, start = _parse_supplemental_from_tail(frame)
        assert suppl.nonce_32 == 42
        assert suppl.tag_8 == b"\xDD" * 8
        assert suppl.unencrypted_ranges == []
        assert start == 10

    def test_with_ranges(self):
        ranges = [UnencryptedRange(offset=0, length=3), UnencryptedRange(offset=5, length=2)]
        frame = self._build_protocol_frame(b"\xEE" * 20, b"\xFF" * 8, 100, ranges)
        suppl, _ = _parse_supplemental_from_tail(frame)
        assert len(suppl.unencrypted_ranges) == 2
        assert suppl.nonce_32 == 100

    def test_too_short_raises(self):
        with pytest.raises(DecryptionError, match="too short"):
            _parse_supplemental_from_tail(b"\x00" * 5)

    def test_bad_magic_raises(self):
        with pytest.raises(DecryptionError, match="magic"):
            _parse_supplemental_from_tail(b"\x00" * 20 + b"\x0B" + b"\x00\x00")

    def test_invalid_suppl_size_raises(self):
        frame = b"\x00" * 20 + b"\x00" + DAVE_MAGIC
        with pytest.raises(DecryptionError, match="supplemental size"):
            _parse_supplemental_from_tail(frame)

    def test_overlapping_ranges_raises(self):
        tag = b"\xAA" * 8
        body = tag + uleb128_encode(0)
        body += uleb128_encode(0) + uleb128_encode(10)
        body += uleb128_encode(5) + uleb128_encode(5)
        suppl_size = len(body) + 3
        frame = b"\x00" * 20 + body + bytes([suppl_size]) + DAVE_MAGIC
        with pytest.raises(DecryptionError, match="Overlapping"):
            _parse_supplemental_from_tail(frame)


# ---------------------------------------------------------------------------
# FrameEncryptor
# ---------------------------------------------------------------------------

class TestFrameEncryptor:
    def test_basic_opus_encrypt(self):
        frame = b"\xAA" * 50
        protocol_frame, _ = encrypt_frame(frame, "OPUS")
        assert protocol_frame[-2:] == DAVE_MAGIC
        assert len(protocol_frame) > len(frame)

    def test_passthrough_mode(self):
        ratchet = make_ratchet()
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet, passthrough=True)
        frame = b"\xBB" * 20
        result = enc.encrypt(frame, "OPUS")
        assert result == frame

    def test_nonce_increments(self):
        ratchet = make_ratchet()
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        frames = [enc.encrypt(b"\x00" * 10, "OPUS") for _ in range(5)]
        assert len(set(frames)) == 5

    def test_generation_wrap(self):
        ratchet = make_ratchet(max_forward_gap=1000)
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        enc._nonce = 0xFFFFFFFF
        result = enc.encrypt(b"\xAA" * 10, "OPUS")
        assert result[-2:] == DAVE_MAGIC
        assert enc._nonce == 0
        assert enc._generation_wrap_count == 1
        result2 = enc.encrypt(b"\xBB" * 10, "OPUS")
        assert result2[-2:] == DAVE_MAGIC

    def test_custom_nonce_supplier(self):
        nonces = iter([0, 0x01000000, 0x02000000])
        ratchet = make_ratchet()
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet, nonce_supplier=lambda: next(nonces))
        r1 = enc.encrypt(b"\xAA" * 10, "OPUS")
        r2 = enc.encrypt(b"\xAA" * 10, "OPUS")
        assert r1 != r2

    def test_vp8_encrypt(self):
        frame = b"\x00" + b"\xAA" * 20
        protocol_frame, _ = encrypt_frame(frame, "VP8")
        assert protocol_frame[-2:] == DAVE_MAGIC

    def test_h264_encrypt(self):
        frame = b"\x00\x00\x01\x67" + b"\xAA" * 20
        protocol_frame, _ = encrypt_frame(frame, "H264")
        assert protocol_frame[-2:] == DAVE_MAGIC

    def test_av1_encrypt_with_transform(self):
        obu1 = bytes([(1 << 3) | 0x02, 0x02, 0xAA, 0xBB])
        obu2 = bytes([(6 << 3) | 0x02, 0x02, 0xCC, 0xDD])
        frame = obu1 + obu2
        protocol_frame, _ = encrypt_frame(frame, "AV1")
        assert protocol_frame[-2:] == DAVE_MAGIC

    def test_empty_frame_encrypt(self):
        protocol_frame, _ = encrypt_frame(b"", "OPUS")
        assert protocol_frame[-2:] == DAVE_MAGIC

    def test_large_frame(self):
        frame = bytes(range(256)) * 40
        protocol_frame, _ = encrypt_frame(frame, "OPUS")
        assert protocol_frame[-2:] == DAVE_MAGIC


# ---------------------------------------------------------------------------
# FrameDecryptor
# ---------------------------------------------------------------------------

class TestFrameDecryptor:
    def _encrypt_then_decrypt(self, frame: bytes, codec: str = "OPUS",
                                secret: bytes = b"\x01" * 16) -> bytes:
        ratchet = make_ratchet(secret)
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        protocol_frame = enc.encrypt(frame, codec)
        dec_ratchet = make_ratchet(secret)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        return dec.decrypt(protocol_frame)

    def test_roundtrip_opus(self):
        frame = b"\xAA" * 50
        assert self._encrypt_then_decrypt(frame, "OPUS") == frame

    def test_roundtrip_vp8_keyframe(self):
        frame = b"\x00" + b"\xBB" * 20
        assert self._encrypt_then_decrypt(frame, "VP8") == frame

    def test_roundtrip_vp8_delta(self):
        frame = b"\x01" + b"\xCC" * 20
        assert self._encrypt_then_decrypt(frame, "VP8") == frame

    def test_roundtrip_h264(self):
        frame = b"\x00\x00\x01\x67" + b"\xDD" * 20
        assert self._encrypt_then_decrypt(frame, "H264") == frame

    def test_roundtrip_h265(self):
        vps_byte = (32 << 1) & 0x7E
        frame = b"\x00\x00\x01" + bytes([vps_byte, 0x00]) + b"\xEE" * 20
        assert self._encrypt_then_decrypt(frame, "H265") == frame

    def test_roundtrip_vp9(self):
        frame = b"\xFF" * 100
        assert self._encrypt_then_decrypt(frame, "VP9") == frame

    def test_roundtrip_empty(self):
        assert self._encrypt_then_decrypt(b"", "OPUS") == b""

    def test_roundtrip_large(self):
        frame = bytes(range(256)) * 40
        assert self._encrypt_then_decrypt(frame, "OPUS") == frame

    def test_silence_packet_passthrough(self):
        ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=ratchet)
        result = dec.decrypt(SILENCE_PACKET)
        assert result == SILENCE_PACKET

    def test_nonce_reuse_raises(self):
        ratchet = make_ratchet()
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        protocol_frame = enc.encrypt(b"\xAA" * 10, "OPUS")
        dec_ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        dec.decrypt(protocol_frame)
        with pytest.raises(DecryptionError, match="reuse"):
            dec.decrypt(protocol_frame)

    def test_passthrough_mode_non_protocol_frame(self):
        ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=ratchet, passthrough=True)
        non_protocol = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E"
        result = dec.decrypt(non_protocol)
        assert result == non_protocol

    def test_passthrough_mode_protocol_frame_decrypted(self):
        secret = b"\x01" * 16
        ratchet = make_ratchet(secret)
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        frame = b"\xAA" * 20
        protocol_frame = enc.encrypt(frame, "OPUS")
        dec_ratchet = make_ratchet(secret)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet, passthrough=True)
        result = dec.decrypt(protocol_frame)
        assert result == frame

    def test_wrong_key_raises(self):
        ratchet = make_ratchet(b"\x01" * 16)
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        protocol_frame = enc.encrypt(b"\xAA" * 10, "OPUS")
        bad_ratchet = make_ratchet(b"\x02" * 16)
        dec = FrameDecryptor(sender_user_id=1, ratchet=bad_ratchet)
        with pytest.raises(DecryptionError):
            dec.decrypt(protocol_frame)

    def test_tampered_ciphertext_raises(self):
        ratchet = make_ratchet()
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        protocol_frame = enc.encrypt(b"\xAA" * 20, "OPUS")
        tampered = bytearray(protocol_frame)
        tampered[0] ^= 0xFF
        dec_ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        with pytest.raises(DecryptionError):
            dec.decrypt(bytes(tampered))

    def test_multiple_frames_sequential(self):
        secret = b"\x01" * 16
        ratchet = make_ratchet(secret)
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet)
        frames = [bytes([i]) * 10 for i in range(10)]
        protocol_frames = [enc.encrypt(f, "OPUS") for f in frames]
        dec_ratchet = make_ratchet(secret)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        for i, pf in enumerate(protocol_frames):
            result = dec.decrypt(pf)
            assert result == frames[i]


class TestFrameDecryptorNonceWrap:
    """Test nonce wrap-around generation tracking in decryptor."""

    def test_wrap_count_increments(self):
        ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=ratchet)
        assert dec._wrap_count == 0
        assert dec._seen_high_nonce is False

    def test_generation_from_nonce_basic(self):
        ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=ratchet)
        assert dec._generation_from_nonce(0x00000000) == 0
        assert dec._generation_from_nonce(0x01000000) == 1
        assert dec._generation_from_nonce(0xFF000000) == 255

    def test_generation_from_nonce_after_wrap(self):
        ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=ratchet)
        dec._wrap_count = 1
        assert dec._generation_from_nonce(0x00000000) == 256
        assert dec._generation_from_nonce(0x01000000) == 257
        assert dec._generation_from_nonce(0xFF000000) == 511

    def test_apply_nonce_seen_triggers_wrap(self):
        ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=ratchet)
        dec._apply_nonce_seen(0xFF000000)
        assert dec._seen_high_nonce is True
        assert dec._wrap_count == 0
        dec._apply_nonce_seen(0x00000000)
        assert dec._wrap_count == 1
        assert dec._seen_high_nonce is False

    def test_seen_high_nonce_without_wrap_returns_256(self):
        ratchet = make_ratchet()
        dec = FrameDecryptor(sender_user_id=1, ratchet=ratchet)
        dec._seen_high_nonce = True
        assert dec._generation_from_nonce(0x00000000) == 256


# ---------------------------------------------------------------------------
# protocol_frame_check
# ---------------------------------------------------------------------------

class TestProtocolFrameCheck:
    def _make_valid_frame(self, nonce: int = 0,
                           ranges: list[UnencryptedRange] | None = None) -> bytes:
        if ranges is None:
            ranges = []
        tag = b"\xAA" * 8
        body = _build_supplemental_footer(tag, nonce, ranges)
        suppl_size = len(body) + 3
        interleaved = b"\x00" * 20
        return interleaved + body + bytes([suppl_size]) + DAVE_MAGIC

    def test_valid_frame(self):
        assert protocol_frame_check(self._make_valid_frame()) is True

    def test_valid_with_ranges(self):
        ranges = [UnencryptedRange(offset=0, length=5), UnencryptedRange(offset=10, length=3)]
        assert protocol_frame_check(self._make_valid_frame(42, ranges)) is True

    def test_too_short(self):
        assert protocol_frame_check(b"\x00" * 5) is False

    def test_bad_magic(self):
        frame = self._make_valid_frame()
        bad = frame[:-2] + b"\x00\x00"
        assert protocol_frame_check(bad) is False

    def test_suppl_size_too_small(self):
        body = b"\xAA" * 8 + uleb128_encode(0)
        frame = b"\x00" * 20 + body + bytes([5]) + DAVE_MAGIC
        assert protocol_frame_check(frame) is False

    def test_suppl_size_too_large(self):
        body = b"\xAA" * 8 + uleb128_encode(0)
        frame = body + bytes([255]) + DAVE_MAGIC
        assert protocol_frame_check(frame) is False

    def test_nonce_overflow_32bit(self):
        tag = b"\xAA" * 8
        big_nonce = uleb128_encode(0x1FFFFFFFF)
        body = tag + big_nonce
        suppl_size = len(body) + 3
        frame = b"\x00" * 20 + body + bytes([suppl_size]) + DAVE_MAGIC
        assert protocol_frame_check(frame) is False

    def test_overlapping_ranges(self):
        tag = b"\xAA" * 8
        body = tag + uleb128_encode(0)
        body += uleb128_encode(0) + uleb128_encode(10)
        body += uleb128_encode(5) + uleb128_encode(5)  # overlaps
        suppl_size = len(body) + 3
        frame = b"\x00" * 30 + body + bytes([suppl_size]) + DAVE_MAGIC
        assert protocol_frame_check(frame) is False

    def test_range_exceeds_interleaved_bounds(self):
        tag = b"\xAA" * 8
        body = tag + uleb128_encode(0)
        body += uleb128_encode(0) + uleb128_encode(100)  # exceeds interleaved (5 bytes)
        suppl_size = len(body) + 3
        frame = b"\x00" * 5 + body + bytes([suppl_size]) + DAVE_MAGIC
        assert protocol_frame_check(frame) is False

    def test_non_protocol_frame(self):
        assert protocol_frame_check(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C") is False

    def test_silence_packet_not_protocol(self):
        assert protocol_frame_check(SILENCE_PACKET) is False


class TestSilencePacket:
    def test_value(self):
        assert SILENCE_PACKET == bytes((0xF8, 0xFF, 0xFE))

    def test_length(self):
        assert len(SILENCE_PACKET) == 3
