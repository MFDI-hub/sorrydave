"""Comprehensive cipher tests: nonce expansion, GCM encrypt/decrypt, interleaved ranges, edge cases."""

import pytest

from sorrydave.crypto.cipher import (
    DAVE_MAGIC,
    GCM_TAG_LENGTH,
    decrypt_interleaved,
    encrypt_interleaved,
    expand_nonce_96,
)
from sorrydave.exceptions import DecryptionError
from sorrydave.types import UnencryptedRange


class TestExpandNonce96:
    def test_zero_nonce(self):
        nonce = expand_nonce_96(0)
        assert len(nonce) == 12
        assert nonce == b"\x00" * 12

    def test_max_nonce(self):
        nonce = expand_nonce_96(0xFFFFFFFF)
        assert len(nonce) == 12
        assert nonce[:8] == b"\x00" * 8
        assert nonce[8:] == (0xFFFFFFFF).to_bytes(4, "little")

    def test_nonce_1(self):
        nonce = expand_nonce_96(1)
        assert nonce == b"\x00" * 8 + b"\x01\x00\x00\x00"

    def test_little_endian_byte_order(self):
        nonce = expand_nonce_96(0x01020304)
        assert nonce[8:] == bytes([0x04, 0x03, 0x02, 0x01])

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            expand_nonce_96(-1)

    def test_overflow_raises(self):
        with pytest.raises(ValueError):
            expand_nonce_96(0x100000000)


class TestEncryptDecryptFull:
    KEY = b"\x01" * 16

    def test_roundtrip_simple(self):
        plaintext = b"Hello, DAVE!"
        interleaved, tag = encrypt_interleaved(self.KEY, 0, plaintext, [])
        result = decrypt_interleaved(self.KEY, 0, interleaved, tag, [])
        assert result == plaintext

    def test_empty_frame(self):
        interleaved, tag = encrypt_interleaved(self.KEY, 0, b"", [])
        result = decrypt_interleaved(self.KEY, 0, interleaved, tag, [])
        assert result == b""

    def test_tag_length(self):
        _, tag = encrypt_interleaved(self.KEY, 0, b"data", [])
        assert len(tag) == GCM_TAG_LENGTH

    def test_different_nonces_produce_different_ciphertext(self):
        plaintext = b"same data"
        ct1, _ = encrypt_interleaved(self.KEY, 0, plaintext, [])
        ct2, _ = encrypt_interleaved(self.KEY, 1, plaintext, [])
        assert ct1 != ct2

    def test_different_keys_cannot_decrypt(self):
        other_key = b"\x02" * 16
        interleaved, tag = encrypt_interleaved(self.KEY, 0, b"secret", [])
        with pytest.raises(DecryptionError):
            decrypt_interleaved(other_key, 0, interleaved, tag, [])

    def test_wrong_tag_fails(self):
        interleaved, tag = encrypt_interleaved(self.KEY, 0, b"data", [])
        bad_tag = bytes(b ^ 0xFF for b in tag)
        with pytest.raises(DecryptionError):
            decrypt_interleaved(self.KEY, 0, interleaved, bad_tag, [])

    def test_wrong_nonce_fails(self):
        interleaved, tag = encrypt_interleaved(self.KEY, 0, b"data", [])
        with pytest.raises(DecryptionError):
            decrypt_interleaved(self.KEY, 1, interleaved, tag, [])

    def test_truncated_tag_fails(self):
        interleaved, tag = encrypt_interleaved(self.KEY, 0, b"data", [])
        with pytest.raises(DecryptionError):
            decrypt_interleaved(self.KEY, 0, interleaved, tag[:4], [])

    def test_large_payload(self):
        plaintext = bytes(range(256)) * 100
        interleaved, tag = encrypt_interleaved(self.KEY, 42, plaintext, [])
        result = decrypt_interleaved(self.KEY, 42, interleaved, tag, [])
        assert result == plaintext

    def test_max_nonce_value(self):
        plaintext = b"edge"
        interleaved, tag = encrypt_interleaved(self.KEY, 0xFFFFFFFF, plaintext, [])
        result = decrypt_interleaved(self.KEY, 0xFFFFFFFF, interleaved, tag, [])
        assert result == plaintext


class TestEncryptDecryptInterleaved:
    KEY = b"\xAB" * 16

    def test_single_unencrypted_range_at_start(self):
        frame = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        ranges = [UnencryptedRange(offset=0, length=2)]
        interleaved, tag = encrypt_interleaved(self.KEY, 0, frame, ranges)
        assert interleaved[:2] == frame[:2]
        result = decrypt_interleaved(self.KEY, 0, interleaved, tag, ranges)
        assert result == frame

    def test_single_unencrypted_range_at_end(self):
        frame = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        ranges = [UnencryptedRange(offset=6, length=2)]
        interleaved, tag = encrypt_interleaved(self.KEY, 0, frame, ranges)
        assert interleaved[6:8] == frame[6:8]
        result = decrypt_interleaved(self.KEY, 0, interleaved, tag, ranges)
        assert result == frame

    def test_multiple_unencrypted_ranges(self):
        frame = bytes(range(20))
        ranges = [
            UnencryptedRange(offset=0, length=3),
            UnencryptedRange(offset=10, length=2),
        ]
        interleaved, tag = encrypt_interleaved(self.KEY, 5, frame, ranges)
        assert interleaved[:3] == frame[:3]
        assert interleaved[10:12] == frame[10:12]
        result = decrypt_interleaved(self.KEY, 5, interleaved, tag, ranges)
        assert result == frame

    def test_entire_frame_unencrypted(self):
        frame = b"\xAA\xBB\xCC"
        ranges = [UnencryptedRange(offset=0, length=3)]
        interleaved, tag = encrypt_interleaved(self.KEY, 0, frame, ranges)
        assert interleaved == frame
        result = decrypt_interleaved(self.KEY, 0, interleaved, tag, ranges)
        assert result == frame

    def test_aad_tamper_fails(self):
        frame = b"\x01\x02\x03\x04\x05\x06"
        ranges = [UnencryptedRange(offset=0, length=2)]
        interleaved, tag = encrypt_interleaved(self.KEY, 0, frame, ranges)
        tampered = bytearray(interleaved)
        tampered[0] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt_interleaved(self.KEY, 0, bytes(tampered), tag, ranges)

    def test_ciphertext_tamper_fails(self):
        frame = b"\x01\x02\x03\x04\x05\x06"
        ranges = [UnencryptedRange(offset=0, length=2)]
        interleaved, tag = encrypt_interleaved(self.KEY, 0, frame, ranges)
        tampered = bytearray(interleaved)
        tampered[3] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt_interleaved(self.KEY, 0, bytes(tampered), tag, ranges)

    def test_adjacent_ranges(self):
        frame = bytes(range(10))
        ranges = [
            UnencryptedRange(offset=2, length=2),
            UnencryptedRange(offset=4, length=3),
        ]
        interleaved, tag = encrypt_interleaved(self.KEY, 0, frame, ranges)
        result = decrypt_interleaved(self.KEY, 0, interleaved, tag, ranges)
        assert result == frame


class TestProtocolConstants:
    def test_magic_marker(self):
        assert DAVE_MAGIC == b"\xFA\xFA"

    def test_gcm_tag_length(self):
        assert GCM_TAG_LENGTH == 8
