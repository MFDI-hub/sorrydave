"""
End-to-end protocol tests: full DAVE frame encrypt/decrypt cycles with
protocol-realistic parameters, codec handling, key ratcheting, epoch
transitions, and edge cases.

These tests simulate what actually happens in a Discord voice session:
Discord sends a 32-byte secret_key in op 4, the library derives per-sender
16-byte keys via HKDF, and frames are encrypted/decrypted with AES128-GCM
using the DAVE supplemental footer format.
"""

from __future__ import annotations

import orjson

import pytest

from sorrydave.crypto.cipher import (
    DAVE_MAGIC,
    GCM_TAG_LENGTH,
    decrypt_interleaved,
    encrypt_interleaved,
    expand_nonce_96,
    uleb128_decode,
    uleb128_encode,
)
from sorrydave.crypto.ratchet import KEY_LENGTH, RATCHET_LABEL, KeyRatchet
from sorrydave.exceptions import DecryptionError
from sorrydave.media.codecs import get_unencrypted_ranges
from sorrydave.media.transform import (
    MIN_SUPPLEMENTAL,
    SILENCE_PACKET,
    FrameDecryptor,
    FrameEncryptor,
    protocol_frame_check,
)
from sorrydave.types import ProtocolSupplementalData, UnencryptedRange

# Real secret_key from idk capture (op 4)
REAL_SECRET_KEY = bytes(
    [
        254,
        118,
        6,
        145,
        6,
        5,
        71,
        9,
        200,
        63,
        91,
        105,
        46,
        188,
        124,
        39,
        34,
        0,
        41,
        49,
        173,
        135,
        77,
        7,
        104,
        74,
        50,
        97,
        125,
        113,
        180,
        145,
    ]
)


def _make_ratchet(secret: bytes = None) -> KeyRatchet:
    base = (secret or REAL_SECRET_KEY)[:KEY_LENGTH]
    return KeyRatchet(base, retention_seconds=10.0, max_forward_gap=256)


def _make_pair(
    user_id: int = 256062279974387723,
    secret: bytes = None,
) -> tuple[FrameEncryptor, FrameDecryptor]:
    ratchet_enc = _make_ratchet(secret)
    ratchet_dec = _make_ratchet(secret)
    enc = FrameEncryptor(sender_user_id=user_id, ratchet=ratchet_enc)
    dec = FrameDecryptor(sender_user_id=user_id, ratchet=ratchet_dec)
    return enc, dec


class TestRatchetWithRealKey:
    """Key ratchet using the real 32-byte secret from a Discord session."""

    def test_derives_16_byte_keys(self):
        ratchet = _make_ratchet()
        key = ratchet.get_key_for_generation(0)
        assert isinstance(key, bytes)
        assert len(key) == 16

    def test_deterministic(self):
        r1 = _make_ratchet()
        r2 = _make_ratchet()
        assert r1.get_key_for_generation(0) == r2.get_key_for_generation(0)
        assert r1.get_key_for_generation(1) == r2.get_key_for_generation(1)

    def test_different_generations_different_keys(self):
        ratchet = _make_ratchet()
        keys = {ratchet.get_key_for_generation(g) for g in range(10)}
        assert len(keys) == 10

    def test_epoch_advance_changes_keys(self):
        ratchet = _make_ratchet()
        key_before = ratchet.get_key_for_generation(0)
        new_secret = b"\x01" * 16
        ratchet.advance_epoch(new_secret)
        key_after = ratchet.get_key_for_generation(0)
        assert key_before != key_after


class TestEncryptDecryptOpus:
    """Full OPUS frame encrypt/decrypt cycle (fully encrypted, no unencrypted ranges)."""

    def test_roundtrip_small_frame(self):
        enc, dec = _make_pair()
        frame = b"\xfc\x00\x01\x02\x03\x04\x05\x06\x07"
        encrypted = enc.encrypt(frame, "opus")
        assert encrypted != frame
        assert encrypted[-2:] == DAVE_MAGIC
        assert protocol_frame_check(encrypted)
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame

    def test_roundtrip_20ms_opus_frame(self):
        enc, dec = _make_pair()
        frame = bytes(range(256)) * 3  # ~768 bytes, typical 20ms OPUS
        encrypted = enc.encrypt(frame, "opus")
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame

    def test_roundtrip_silence(self):
        enc, dec = _make_pair()
        decrypted = dec.decrypt(SILENCE_PACKET)
        assert decrypted == SILENCE_PACKET

    def test_multiple_frames_sequential(self):
        enc, dec = _make_pair()
        for i in range(50):
            frame = bytes([i & 0xFF]) * (20 + i)
            encrypted = enc.encrypt(frame, "opus")
            decrypted = dec.decrypt(encrypted)
            assert decrypted == frame

    def test_nonce_increments(self):
        enc, dec = _make_pair()
        frames = []
        for i in range(5):
            frame = bytes([i]) * 20
            encrypted = enc.encrypt(frame, "opus")
            frames.append(encrypted)
        # Each should have a different nonce in the footer
        nonces = set()
        for f in frames:
            suppl_size = f[-3]
            body = f[len(f) - suppl_size : len(f) - 3]
            nonce, _ = uleb128_decode(body, 8)
            nonces.add(nonce)
        assert len(nonces) == 5


class TestEncryptDecryptVP8:
    """VP8 frame encrypt/decrypt (1 or 10 bytes unencrypted header)."""

    def test_delta_frame_1_byte_unencrypted(self):
        enc, dec = _make_pair()
        # VP8 delta frame: P=1 (not keyframe) -> 1 byte unencrypted
        frame = b"\x31" + b"\xaa" * 100  # P bit set (bit 0 = 1)
        encrypted = enc.encrypt(frame, "VP8")
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame

    def test_keyframe_10_bytes_unencrypted(self):
        enc, dec = _make_pair()
        # VP8 keyframe: P=0 -> 10 bytes unencrypted
        frame = b"\x30" + b"\x00" * 9 + b"\xbb" * 100
        encrypted = enc.encrypt(frame, "VP8")
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame


class TestEncryptDecryptH264:
    """H264 frame encrypt/decrypt with NAL unit handling."""

    def test_simple_h264_frame(self):
        enc, dec = _make_pair()
        # H264 frame with start code + NAL header + payload
        frame = b"\x00\x00\x00\x01\x65" + b"\xcc" * 200
        encrypted = enc.encrypt(frame, "H264")
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame

    def test_h265_alias(self):
        enc, dec = _make_pair()
        frame = b"\x00\x00\x00\x01\x26\x01" + b"\xdd" * 100
        encrypted = enc.encrypt(frame, "H265")
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame


class TestEncryptDecryptVP9:
    """VP9 frames are fully encrypted."""

    def test_roundtrip(self):
        enc, dec = _make_pair()
        frame = b"\x82\x49\x83\x42\x00" + b"\xee" * 150
        encrypted = enc.encrypt(frame, "VP9")
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame


class TestEncryptDecryptAV1:
    """AV1 frame encrypt/decrypt with OBU handling."""

    def test_simple_av1(self):
        enc, dec = _make_pair()
        obu_type_frame = 0x32  # OBU type 6 (frame) with obu_has_size_field=1
        payload = b"\xaa" * 50
        size_byte = len(payload)
        frame = bytes([obu_type_frame, size_byte]) + payload
        encrypted = enc.encrypt(frame, "AV1")
        decrypted = dec.decrypt(encrypted)
        assert len(decrypted) > 0


class TestProtocolFrameStructure:
    """Verify the DAVE protocol frame structure matches protocol.md."""

    def test_footer_has_magic(self):
        enc, _ = _make_pair()
        frame = b"\x00" * 20
        encrypted = enc.encrypt(frame, "opus")
        assert encrypted[-2:] == b"\xfa\xfa"

    def test_footer_supplemental_size(self):
        enc, _ = _make_pair()
        frame = b"\x00" * 20
        encrypted = enc.encrypt(frame, "opus")
        suppl_size = encrypted[-3]
        assert (
            suppl_size >= 11
        )  # min: 8 tag + 1 nonce + 1 size + 2 magic - but size counts differently
        assert suppl_size < len(encrypted)

    def test_footer_contains_8_byte_tag(self):
        enc, _ = _make_pair()
        frame = b"\x00" * 20
        encrypted = enc.encrypt(frame, "opus")
        suppl_size = encrypted[-3]
        body_start = len(encrypted) - suppl_size
        body = encrypted[body_start : len(encrypted) - 3]
        tag = body[:8]
        assert len(tag) == GCM_TAG_LENGTH

    def test_footer_contains_uleb128_nonce(self):
        enc, _ = _make_pair()
        frame = b"\x00" * 20
        encrypted = enc.encrypt(frame, "opus")
        suppl_size = encrypted[-3]
        body_start = len(encrypted) - suppl_size
        body = encrypted[body_start : len(encrypted) - 3]
        nonce, offset = uleb128_decode(body, 8)
        assert nonce == 0  # first frame
        assert offset > 8

    def test_protocol_frame_check_on_encrypted(self):
        enc, _ = _make_pair()
        frame = b"\xaa" * 50
        encrypted = enc.encrypt(frame, "opus")
        assert protocol_frame_check(encrypted) is True

    def test_protocol_frame_check_on_raw(self):
        assert protocol_frame_check(b"\xaa" * 50) is False

    def test_protocol_frame_check_on_short(self):
        assert protocol_frame_check(b"\xfa\xfa") is False

    def test_protocol_frame_check_on_silence(self):
        assert protocol_frame_check(SILENCE_PACKET) is False


class TestNonceExpansion:
    """Verify 32-bit -> 96-bit nonce expansion per protocol.md."""

    def test_zero_nonce(self):
        full = expand_nonce_96(0)
        assert len(full) == 12
        assert full == b"\x00" * 12

    def test_nonzero_nonce(self):
        full = expand_nonce_96(0x01020304)
        assert len(full) == 12
        assert full[:8] == b"\x00" * 8
        # Little-endian 4 bytes
        assert full[8:] == (0x01020304).to_bytes(4, "little")

    def test_max_nonce(self):
        full = expand_nonce_96(0xFFFFFFFF)
        assert len(full) == 12
        assert full[8:] == b"\xff\xff\xff\xff"


class TestUleb128ProtocolUsage:
    """ULEB128 encoding as used in DAVE protocol supplemental data."""

    def test_small_nonce(self):
        encoded = uleb128_encode(0)
        assert encoded == b"\x00"
        val, _ = uleb128_decode(encoded)
        assert val == 0

    def test_nonce_127(self):
        encoded = uleb128_encode(127)
        assert len(encoded) == 1
        val, _ = uleb128_decode(encoded)
        assert val == 127

    def test_nonce_128(self):
        encoded = uleb128_encode(128)
        assert len(encoded) == 2
        val, _ = uleb128_decode(encoded)
        assert val == 128

    def test_max_32bit_nonce(self):
        encoded = uleb128_encode(0xFFFFFFFF)
        val, _ = uleb128_decode(encoded)
        assert val == 0xFFFFFFFF

    def test_roundtrip_range(self):
        for v in [0, 1, 63, 64, 127, 128, 255, 256, 16383, 16384, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF]:
            encoded = uleb128_encode(v)
            decoded, _ = uleb128_decode(encoded)
            assert decoded == v


class TestKeyRatchetGeneration:
    """Key generation from nonce MSB (protocol: generation = nonce >> 24)."""

    def test_generation_0(self):
        ratchet = _make_ratchet()
        key = ratchet.get_key_for_generation(0)
        assert len(key) == 16

    def test_generation_255(self):
        ratchet = _make_ratchet()
        key = ratchet.get_key_for_generation(255)
        assert len(key) == 16

    def test_generation_from_nonce_msb(self):
        ratchet = _make_ratchet()
        for nonce in [0x00000000, 0x01000000, 0x02000000, 0xFF000000]:
            generation = (nonce >> 24) & 0xFF
            key = ratchet.get_key_for_generation(generation)
            assert len(key) == 16


class TestDecryptionErrors:
    """Verify proper error handling on tampered/invalid frames."""

    def test_wrong_key_fails(self):
        enc, _ = _make_pair(secret=b"\xaa" * 16)
        _, dec = _make_pair(secret=b"\xbb" * 16)
        encrypted = enc.encrypt(b"\x00" * 20, "opus")
        with pytest.raises(DecryptionError):
            dec.decrypt(encrypted)

    def test_tampered_ciphertext_fails(self):
        enc, dec = _make_pair()
        encrypted = enc.encrypt(b"\x00" * 20, "opus")
        tampered = bytearray(encrypted)
        tampered[0] ^= 0xFF
        with pytest.raises(DecryptionError):
            dec.decrypt(bytes(tampered))

    def test_tampered_tag_fails(self):
        enc, dec = _make_pair()
        encrypted = enc.encrypt(b"\x00" * 20, "opus")
        tampered = bytearray(encrypted)
        suppl_size = tampered[-3]
        tag_start = len(tampered) - suppl_size
        tampered[tag_start] ^= 0xFF
        with pytest.raises(DecryptionError):
            dec.decrypt(bytes(tampered))

    def test_truncated_frame_fails(self):
        enc, dec = _make_pair()
        encrypted = enc.encrypt(b"\x00" * 20, "opus")
        with pytest.raises(DecryptionError):
            dec.decrypt(encrypted[:5])

    def test_nonce_reuse_rejected(self):
        enc, dec = _make_pair()
        encrypted = enc.encrypt(b"\x00" * 20, "opus")
        dec.decrypt(encrypted)
        with pytest.raises(DecryptionError, match="[Nn]once reuse"):
            dec.decrypt(encrypted)


class TestPassthroughMode:
    """Passthrough mode: non-DAVE frames pass through, DAVE frames are decrypted."""

    def test_passthrough_raw_frame(self):
        dec = FrameDecryptor(sender_user_id=1, ratchet=_make_ratchet(), passthrough=True)
        raw = b"\x01\x02\x03\x04\x05" * 10
        result = dec.decrypt(raw)
        assert result == raw

    def test_passthrough_silence(self):
        dec = FrameDecryptor(sender_user_id=1, ratchet=_make_ratchet(), passthrough=True)
        result = dec.decrypt(SILENCE_PACKET)
        assert result == SILENCE_PACKET

    def test_passthrough_still_decrypts_dave_frames(self):
        enc, _ = _make_pair()
        dec = FrameDecryptor(
            sender_user_id=256062279974387723,
            ratchet=_make_ratchet(),
            passthrough=True,
        )
        frame = b"\xaa" * 50
        encrypted = enc.encrypt(frame, "opus")
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame

    def test_non_passthrough_rejects_raw(self):
        dec = FrameDecryptor(sender_user_id=1, ratchet=_make_ratchet(), passthrough=False)
        raw = b"\x01\x02\x03\x04\x05" * 10
        with pytest.raises(DecryptionError):
            dec.decrypt(raw)


class TestEpochTransition:
    """Simulate epoch transition: new ratchet with fallback to previous."""

    def test_fallback_ratchet_decrypts_inflight(self):
        import time

        old_secret = REAL_SECRET_KEY[:16]
        new_secret = b"\x01" * 16

        old_ratchet = KeyRatchet(old_secret, retention_seconds=10.0, max_forward_gap=256)
        enc = FrameEncryptor(sender_user_id=1, ratchet=old_ratchet)
        encrypted = enc.encrypt(b"\xaa" * 30, "opus")

        old_fb = KeyRatchet(old_secret, retention_seconds=10.0, max_forward_gap=256)
        new_ratchet = KeyRatchet(new_secret, retention_seconds=10.0, max_forward_gap=256)
        dec = FrameDecryptor(
            sender_user_id=1,
            ratchet=new_ratchet,
            fallback_ratchets=[(time.monotonic() + 10.0, old_fb)],
        )
        decrypted = dec.decrypt(encrypted)
        assert decrypted == b"\xaa" * 30


class TestMultipleSenders:
    """Multiple senders with different keys."""

    def test_two_senders(self):
        secret_a = b"\xaa" * 16
        secret_b = b"\xbb" * 16

        enc_a = FrameEncryptor(sender_user_id=1, ratchet=KeyRatchet(secret_a))
        enc_b = FrameEncryptor(sender_user_id=2, ratchet=KeyRatchet(secret_b))

        dec_a = FrameDecryptor(sender_user_id=1, ratchet=KeyRatchet(secret_a))
        dec_b = FrameDecryptor(sender_user_id=2, ratchet=KeyRatchet(secret_b))

        frame_a = b"\x01" * 30
        frame_b = b"\x02" * 30

        enc_a_out = enc_a.encrypt(frame_a, "opus")
        enc_b_out = enc_b.encrypt(frame_b, "opus")

        assert dec_a.decrypt(enc_a_out) == frame_a
        assert dec_b.decrypt(enc_b_out) == frame_b

    def test_cross_sender_fails(self):
        secret_a = b"\xaa" * 16
        secret_b = b"\xbb" * 16

        enc_a = FrameEncryptor(sender_user_id=1, ratchet=KeyRatchet(secret_a))
        dec_b = FrameDecryptor(sender_user_id=2, ratchet=KeyRatchet(secret_b))

        encrypted = enc_a.encrypt(b"\x01" * 30, "opus")
        with pytest.raises(DecryptionError):
            dec_b.decrypt(encrypted)


class TestCodecUnencryptedRanges:
    """Verify codec-aware unencrypted range handling matches protocol.md."""

    def test_opus_fully_encrypted(self):
        ranges = get_unencrypted_ranges(b"\xfc\x00" * 10, "opus")
        assert ranges == []

    def test_vp9_fully_encrypted(self):
        ranges = get_unencrypted_ranges(b"\x82" * 10, "VP9")
        assert ranges == []

    def test_vp8_keyframe_10_bytes(self):
        frame = b"\x30" + b"\x00" * 9 + b"\xaa" * 50
        ranges = get_unencrypted_ranges(frame, "VP8")
        total_unenc = sum(r.length for r in ranges)
        assert total_unenc == 10

    def test_vp8_delta_1_byte(self):
        frame = b"\x31" + b"\xaa" * 50
        ranges = get_unencrypted_ranges(frame, "VP8")
        total_unenc = sum(r.length for r in ranges)
        assert total_unenc == 1

    def test_case_insensitive(self):
        frame = b"\xfc\x00" * 10
        assert get_unencrypted_ranges(frame, "OPUS") == get_unencrypted_ranges(frame, "opus")

    def test_unknown_codec_fully_encrypted(self):
        frame = b"\x00" * 20
        ranges = get_unencrypted_ranges(frame, "UNKNOWN")
        assert ranges == []


class TestInterleaveEncryptDecrypt:
    """Direct test of interleaved encrypt/decrypt (cipher layer)."""

    def test_no_ranges_full_encrypt(self):
        key = _make_ratchet().get_key_for_generation(0)
        frame = b"\xaa" * 50
        interleaved, tag = encrypt_interleaved(key, 0, frame, [])
        assert interleaved != frame
        decrypted = decrypt_interleaved(key, 0, interleaved, tag, [])
        assert decrypted == frame

    def test_with_unencrypted_ranges(self):
        key = _make_ratchet().get_key_for_generation(0)
        frame = b"\x00" * 10 + b"\xaa" * 40
        ranges = [UnencryptedRange(offset=0, length=10)]
        interleaved, tag = encrypt_interleaved(key, 0, frame, ranges)
        # First 10 bytes should be unchanged (unencrypted)
        assert interleaved[:10] == b"\x00" * 10
        # Rest should be encrypted
        assert interleaved[10:] != b"\xaa" * 40
        decrypted = decrypt_interleaved(key, 0, interleaved, tag, ranges)
        assert decrypted == frame

    def test_multiple_unencrypted_ranges(self):
        key = _make_ratchet().get_key_for_generation(0)
        frame = b"\x01" * 5 + b"\xaa" * 10 + b"\x02" * 5 + b"\xbb" * 10
        ranges = [
            UnencryptedRange(offset=0, length=5),
            UnencryptedRange(offset=15, length=5),
        ]
        interleaved, tag = encrypt_interleaved(key, 42, frame, ranges)
        assert interleaved[:5] == b"\x01" * 5
        assert interleaved[15:20] == b"\x02" * 5
        decrypted = decrypt_interleaved(key, 42, interleaved, tag, ranges)
        assert decrypted == frame


class TestEncryptorPassthrough:
    """FrameEncryptor passthrough mode returns frames unchanged."""

    def test_passthrough_returns_same(self):
        ratchet = _make_ratchet()
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet, passthrough=True)
        frame = b"\xaa" * 50
        result = enc.encrypt(frame, "opus")
        assert result == frame

    def test_non_passthrough_encrypts(self):
        ratchet = _make_ratchet()
        enc = FrameEncryptor(sender_user_id=1, ratchet=ratchet, passthrough=False)
        frame = b"\xaa" * 50
        result = enc.encrypt(frame, "opus")
        assert result != frame
        assert result[-2:] == DAVE_MAGIC


class TestAllCodecsRoundtrip:
    """Parametrized roundtrip test for all supported codecs."""

    @pytest.mark.parametrize(
        "codec,frame",
        [
            ("opus", b"\xfc\x00" + b"\xaa" * 100),
            ("VP8", b"\x31" + b"\xbb" * 100),
            ("VP8", b"\x30" + b"\x00" * 9 + b"\xcc" * 100),
            ("VP9", b"\x82\x49\x83\x42\x00" + b"\xdd" * 100),
            ("H264", b"\x00\x00\x00\x01\x65" + b"\xee" * 100),
            ("H265", b"\x00\x00\x00\x01\x26\x01" + b"\xff" * 100),
        ],
        ids=["opus", "vp8-delta", "vp8-key", "vp9", "h264", "h265"],
    )
    def test_roundtrip(self, codec: str, frame: bytes):
        enc, dec = _make_pair()
        encrypted = enc.encrypt(frame, codec)
        assert protocol_frame_check(encrypted)
        decrypted = dec.decrypt(encrypted)
        assert decrypted == frame
