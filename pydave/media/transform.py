"""
Frame encryptor and decryptor: codec-aware transform with DAVE protocol footer.
"""

from typing import Callable, Optional

from pydave.crypto.cipher import (
    DAVE_MAGIC,
    decrypt_interleaved,
    encrypt_interleaved,
    uleb128_decode,
    uleb128_encode,
)
from pydave.crypto.ratchet import KeyRatchet
from pydave.exceptions import DecryptionError
from pydave.media.codecs import get_unencrypted_ranges
from pydave.types import ProtocolSupplementalData, UnencryptedRange

# Minimum footer: 8 tag + 1 nonce byte + 0 ranges + 1 size + 2 magic = 12
MIN_SUPPLEMENTAL = 8 + 1 + 0 + 1 + 2


def _build_supplemental_footer(
    tag_8: bytes,
    nonce_32: int,
    unencrypted_ranges: list[UnencryptedRange],
) -> bytes:
    """Build supplemental blob: tag, ULEB128 nonce, ULEB128 offset/length pairs, then size byte and magic are appended by caller."""
    parts = [tag_8]
    parts.append(uleb128_encode(nonce_32))
    for r in sorted(unencrypted_ranges, key=lambda x: x.offset):
        parts.append(uleb128_encode(r.offset))
        parts.append(uleb128_encode(r.length))
    return b"".join(parts)


def _parse_supplemental_from_tail(frame: bytes) -> tuple[ProtocolSupplementalData, int]:
    """
    Parse supplemental data from the end of a protocol frame.
    Returns (parsed_data, start_offset_of_supplemental).
    Frame ends with: ... [suppl_body][suppl_size_byte][0xFAFA].
    suppl_size includes: tag + nonce + ranges + size_byte + magic (2).
    So suppl_body length = suppl_size - 3 (size byte + magic 2).
    """
    if len(frame) < MIN_SUPPLEMENTAL:
        raise DecryptionError("Frame too short for protocol supplemental data")
    if frame[-2:] != DAVE_MAGIC:
        raise DecryptionError("Invalid magic marker")
    suppl_size = frame[-3]
    if suppl_size < 11 or suppl_size > len(frame):
        raise DecryptionError("Invalid supplemental size")
    # Supplemental content = tag + nonce + ranges; total supplemental = content + 1 (size byte) + 2 (magic)
    suppl_content_start = len(frame) - suppl_size
    if suppl_content_start < 0:
        raise DecryptionError("Supplemental size overflow")
    body = frame[suppl_content_start : len(frame) - 3]
    # body = tag(8) || ULEB128(nonce) || ULEB128(offset)*2*N
    if len(body) < 8:
        raise DecryptionError("Supplemental body too short")
    tag_8 = body[:8]
    offset = 8
    nonce_32, offset = uleb128_decode(body, offset)
    if nonce_32 > 0xFFFFFFFF:
        raise DecryptionError("Nonce overflow")
    ranges: list[UnencryptedRange] = []
    while offset < len(body):
        off_val, offset = uleb128_decode(body, offset)
        if offset > len(body):
            raise DecryptionError("Truncated range in supplemental")
        len_val, offset = uleb128_decode(body, offset)
        ranges.append(UnencryptedRange(offset=off_val, length=len_val))
    # Validate ranges: non-overlapping, sorted
    for i in range(len(ranges) - 1):
        if ranges[i].offset + ranges[i].length > ranges[i + 1].offset:
            raise DecryptionError("Overlapping or unsorted unencrypted ranges")
    data = ProtocolSupplementalData(
        tag_8=tag_8,
        nonce_32=nonce_32,
        unencrypted_ranges=ranges,
        supplemental_size=suppl_size,
    )
    return data, suppl_content_start


class FrameEncryptor:
    """
    Encrypts encoded media frames with codec-aware unencrypted ranges and DAVE footer.
    Uses a key ratchet and monotonic 32-bit nonce for the current sender.
    """

    def __init__(
        self,
        sender_user_id: int,
        ratchet: KeyRatchet,
        nonce_supplier: Optional[Callable[[], int]] = None,
    ):
        self._sender_user_id = sender_user_id
        self._ratchet = ratchet
        self._nonce = 0
        self._nonce_supplier = nonce_supplier  # for tests

    def _next_nonce(self) -> int:
        if self._nonce_supplier is not None:
            return self._nonce_supplier()
        n = self._nonce
        self._nonce += 1
        if self._nonce > 0xFFFFFFFF:
            self._nonce = 0  # wrap; generation will advance in ratchet
        return n

    def encrypt(self, encoded_frame: bytes, codec: str) -> bytes:
        """
        Determine unencrypted ranges from codec, encrypt the frame, append DAVE supplemental footer.
        """
        ranges = get_unencrypted_ranges(encoded_frame, codec)
        nonce_32 = self._next_nonce()
        # Generation = MSB of 32-bit nonce (top byte)
        generation = (nonce_32 >> 24) & 0xFF
        key = self._ratchet.get_key_for_generation(generation)
        interleaved, tag_8 = encrypt_interleaved(key, nonce_32, encoded_frame, ranges)
        footer_body = _build_supplemental_footer(tag_8, nonce_32, ranges)
        suppl_size = len(footer_body) + 1 + 2  # + size byte + magic
        if suppl_size > 255:
            raise DecryptionError("Supplemental data too large")
        return interleaved + footer_body + bytes([suppl_size]) + DAVE_MAGIC


class FrameDecryptor:
    """
    Decrypts DAVE protocol frames: parses footer, looks up key by generation, verifies and decrypts.
    Tracks used (sender_id, nonce) to reject reuse.
    """

    def __init__(self, sender_user_id: int, ratchet: KeyRatchet):
        self._sender_user_id = sender_user_id
        self._ratchet = ratchet
        self._used_nonces: set[tuple[int, int]] = set()

    def decrypt(self, protocol_frame: bytes) -> bytes:
        """
        Parse footer, get key for generation (from nonce MSB), verify tag, decrypt.
        Raises DecryptionError on reuse or verification failure.
        """
        suppl, interleaved_end = _parse_supplemental_from_tail(protocol_frame)
        interleaved = protocol_frame[:interleaved_end]
        if (self._sender_user_id, suppl.nonce_32) in self._used_nonces:
            raise DecryptionError("Nonce reuse")
        generation = (suppl.nonce_32 >> 24) & 0xFF
        key = self._ratchet.get_key_for_generation(generation)
        plain = decrypt_interleaved(
            key,
            suppl.nonce_32,
            interleaved,
            suppl.tag_8,
            suppl.unencrypted_ranges,
        )
        self._used_nonces.add((self._sender_user_id, suppl.nonce_32))
        return plain


def protocol_frame_check(frame: bytes) -> bool:
    """
    Return True if frame passes minimal protocol frame check (magic, size, structure).
    Used by passthrough logic to detect DAVE frames.
    """
    if len(frame) < MIN_SUPPLEMENTAL:
        return False
    if frame[-2:] != DAVE_MAGIC:
        return False
    suppl_size = frame[-3]
    if suppl_size < 11 or suppl_size >= len(frame):
        return False
    return True
