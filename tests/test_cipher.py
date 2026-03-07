import pytest
from sorrydave.crypto.cipher import (
    uleb128_encode,
    uleb128_decode,
    expand_nonce_96,
    encrypt_interleaved,
    decrypt_interleaved,
)
from sorrydave.types import UnencryptedRange
from sorrydave.exceptions import DecryptionError


def test_expand_nonce():
    """expand_nonce_96 produces 12-byte nonce (8 zero bytes + 4-byte LE value)."""
    nonce_12 = expand_nonce_96(0x01020304)
    assert len(nonce_12) == 12
    assert nonce_12[:8] == b"\x00" * 8
    assert nonce_12[8:12] == bytes([4, 3, 2, 1])


def test_encrypt_decrypt_full():
    """Full-frame encrypt/decrypt roundtrip with no unencrypted ranges."""
    key = b"\x00" * 16
    frame = b"hello world"
    interleaved, tag_8 = encrypt_interleaved(key, 0, frame, [])
    assert len(tag_8) == 8
    dec = decrypt_interleaved(key, 0, interleaved, tag_8, [])
    assert dec == frame


def test_encrypt_decrypt_with_ranges():
    key = b"\x01" * 16
    frame = b"AAA" + b"secret" + b"BBB"
    ranges = [UnencryptedRange(0, 3), UnencryptedRange(9, 3)]
    interleaved, tag_8 = encrypt_interleaved(key, 1, frame, ranges)
    dec = decrypt_interleaved(key, 1, interleaved, tag_8, ranges)
    assert dec == frame


def test_wrong_tag_fails():
    """Decryption with wrong GCM tag raises DecryptionError."""
    key = b"\x02" * 16
    frame = b"data"
    interleaved, tag_8 = encrypt_interleaved(key, 0, frame, [])
    wrong_tag = bytes([tag_8[i] ^ 0xFF for i in range(8)])
    with pytest.raises(DecryptionError):
        decrypt_interleaved(key, 0, interleaved, wrong_tag, [])
