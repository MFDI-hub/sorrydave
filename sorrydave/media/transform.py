"""
Frame encryptor and decryptor: codec-aware transform with DAVE protocol footer.
"""

from typing import Callable, Union

from sorrydave.crypto.cipher import (
    DAVE_MAGIC,
    decrypt_interleaved,
    encrypt_interleaved,
    uleb128_decode,
    uleb128_encode,
)
from sorrydave.crypto.ratchet import KeyRatchet
from sorrydave.exceptions import DecryptionError
from sorrydave.media.codecs import get_unencrypted_ranges, transform_av1_frame_for_encrypt
from sorrydave.types import ProtocolSupplementalData, UnencryptedRange

# Minimum footer: 8 tag + 1 nonce byte + 0 ranges + 1 size + 2 magic = 12
MIN_SUPPLEMENTAL = 8 + 1 + 0 + 1 + 2

# H26X: replace 3-byte start code with 4-byte in unencrypted sections; retry encrypt if start code in ciphertext
H26X_START_3 = b"\x00\x00\x01"
H26X_START_4 = b"\x00\x00\x00\x01"
H26X_RETRY_MAX = 10

# Silence packet: SFU-synthesized 3-byte sequence; decryptor passes through per protocol.md
SILENCE_PACKET = bytes((0xF8, 0xFF, 0xFE))


def _replace_3byte_start_with_4byte(data: bytes) -> bytes:
    """
    Replace 3-byte H26x start code with 4-byte in data.

    Args:
        data (bytes): Segment that may contain 0x000001.

    Returns:
        bytes: Data with 0x000001 replaced by 0x00000001.
    """
    out = []
    i = 0
    while i <= len(data) - 3:
        if data[i : i + 3] == H26X_START_3:
            out.append(H26X_START_4)
            i += 3
        else:
            out.append(bytes([data[i]]))
            i += 1
    out.append(data[i:])
    return b"".join(out)


def _apply_h26x_start_code_expansion(
    frame: bytes, ranges: list[UnencryptedRange]
) -> tuple[bytes, list[UnencryptedRange]]:
    """
    Replace 3-byte start codes with 4-byte in unencrypted sections (protocol requirement).

    Args:
        frame (bytes): H264/H265 frame.
        ranges (list[UnencryptedRange]): Unencrypted ranges to expand within.

    Returns:
        tuple[bytes, list[UnencryptedRange]]: (new_frame, new_ranges) with updated offsets/lengths.
    """
    if not ranges:
        return frame, []
    sorted_ranges = sorted(ranges, key=lambda r: r.offset)
    parts = []
    new_ranges: list[UnencryptedRange] = []
    offset_delta = 0
    last = 0
    for r in sorted_ranges:
        parts.append(frame[last : r.offset])
        seg = frame[r.offset : r.offset + r.length]
        expanded = _replace_3byte_start_with_4byte(seg)
        new_len = len(expanded)
        new_ranges.append(UnencryptedRange(offset=r.offset + offset_delta, length=new_len))
        offset_delta += new_len - r.length
        parts.append(expanded)
        last = r.offset + r.length
    parts.append(frame[last:])
    return b"".join(parts), new_ranges


def _contains_h26x_start_code(data: bytes) -> bool:
    """
    Check if H26x start code (3- or 4-byte) appears in data.

    Args:
        data (bytes): Buffer to scan.

    Returns:
        bool: True if 0x000001 or 0x00000001 is present.
    """
    i = 0
    while i <= len(data) - 3:
        if data[i : i + 3] == H26X_START_3:
            return True
        i += 1
    return False


def _build_supplemental_footer(
    tag_8: bytes,
    nonce_32: int,
    unencrypted_ranges: list[UnencryptedRange],
) -> bytes:
    """
    Build supplemental body: tag, ULEB128 nonce, ULEB128 offset/length pairs.

    Caller appends size byte and magic (0xFAFA).

    Args:
        tag_8 (bytes): 8-byte GCM tag.
        nonce_32 (int): 32-bit nonce.
        unencrypted_ranges (list[UnencryptedRange]): Ranges to encode.

    Returns:
        bytes: Supplemental body (without size byte and magic).
    """
    parts = [tag_8]
    parts.append(uleb128_encode(nonce_32))
    for r in sorted(unencrypted_ranges, key=lambda x: x.offset):
        parts.append(uleb128_encode(r.offset))
        parts.append(uleb128_encode(r.length))
    return b"".join(parts)


def _parse_supplemental_from_tail(frame: bytes) -> tuple[ProtocolSupplementalData, int]:
    """
    Parse supplemental data from the end of a protocol frame.

    Frame ends with: ... [suppl_body][suppl_size_byte][0xFAFA]. suppl_size includes
    tag + nonce + ranges + size_byte + magic (2); suppl_body length = suppl_size - 3.

    Args:
        frame (bytes): Full protocol frame (ciphertext + supplemental).

    Returns:
        tuple[ProtocolSupplementalData, int]: (parsed supplemental, start offset of supplemental).

    Raises:
        DecryptionError: If frame too short, invalid magic, or malformed supplemental.
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
        nonce_supplier: Union[Callable[[], int], None] = None,
        passthrough: bool = False,
    ):
        """
        Initialize the frame encryptor.

        Args:
            sender_user_id (int): Sender user ID (e.g. Discord snowflake).
            ratchet (KeyRatchet): Key ratchet for per-generation keys.
            nonce_supplier (Union[Callable[[], int], None]): Optional nonce source for tests.
            passthrough (bool): If True, encrypt() returns frames unchanged (non-E2EE mode).
        """
        self._sender_user_id = sender_user_id
        self._ratchet = ratchet
        self._nonce = 0
        self._generation_wrap_count = 0  # increments when nonce wraps 0xFFFFFFFF -> 0
        self._nonce_supplier = nonce_supplier  # for tests
        self._passthrough = passthrough

    def _next_nonce_and_generation(self) -> tuple[int, int]:
        """
        Return next 32-bit nonce and its generation (from supplier if set, else monotonic).

        Generation continues past 255 when nonce wraps (protocol: "continue incrementing the generation").

        Returns:
            tuple[int, int]: (nonce_32, generation).
        """
        if self._nonce_supplier is not None:
            n = self._nonce_supplier()
            gen = (n >> 24) & 0xFF
            return n, gen
        n = self._nonce
        self._nonce += 1
        if self._nonce > 0xFFFFFFFF:
            self._nonce = 0
            self._generation_wrap_count += 1
        generation = (n >> 24) + self._generation_wrap_count * 256
        return n, generation

    def encrypt(self, encoded_frame: bytes, codec: str) -> bytes:
        """
        Encrypt frame with codec-aware ranges and append DAVE supplemental footer.

        For H264/H265, expands 3-byte start codes to 4-byte in unencrypted sections
        and retries (up to 10 times) if a start code appears in ciphertext or supplemental.

        Args:
            encoded_frame (bytes): Raw encoded frame.
            codec (str): Codec name (e.g. "VP8", "H264").

        Returns:
            bytes: Protocol frame (interleaved ciphertext + supplemental footer).

        Raises:
            DecryptionError: If supplemental too large or H26x retry limit exceeded.
        """
        if self._passthrough:
            return encoded_frame
        codec_upper = (codec or "").strip().upper()
        frame = encoded_frame
        if codec_upper == "AV1":
            frame = transform_av1_frame_for_encrypt(frame)
        ranges = get_unencrypted_ranges(frame, codec)
        if codec_upper in ("H264", "H.264", "H265", "H265/HEVC", "HEVC"):
            frame, ranges = _apply_h26x_start_code_expansion(frame, ranges)
        for _ in range(H26X_RETRY_MAX):
            nonce_32, generation = self._next_nonce_and_generation()
            key = self._ratchet.get_key_for_generation(generation)
            interleaved, tag_8 = encrypt_interleaved(key, nonce_32, frame, ranges)
            footer_body = _build_supplemental_footer(tag_8, nonce_32, ranges)
            if codec_upper in ("H264", "H.264", "H265", "H265/HEVC", "HEVC"):
                if _contains_h26x_start_code(interleaved) or _contains_h26x_start_code(footer_body):
                    continue
            suppl_size = len(footer_body) + 1 + 2
            if suppl_size > 255:
                raise DecryptionError("Supplemental data too large")
            return interleaved + footer_body + bytes([suppl_size]) + DAVE_MAGIC
        raise DecryptionError(
            "H26X start code in ciphertext or supplemental after max retries; frame dropped"
        )


class FrameDecryptor:
    """
    Decrypts DAVE protocol frames.

    Parses footer, looks up key by generation, verifies and decrypts.
    Tracks used (sender_id, nonce) to reject reuse.
    """

    def __init__(self, sender_user_id: int, ratchet: KeyRatchet, passthrough: bool = False):
        """
        Initialize the frame decryptor.

        Args:
            sender_user_id (int): Sender user ID (for nonce reuse tracking).
            ratchet (KeyRatchet): Key ratchet for this sender.
            passthrough (bool): If True, pass through non-protocol and silence frames (non-E2EE mode).
        """
        self._sender_user_id = sender_user_id
        self._ratchet = ratchet
        self._used_nonces: set[tuple[int, int]] = set()
        self._passthrough = passthrough
        # For nonce wrap: generation continues past 255 (protocol)
        self._wrap_count = 0
        self._seen_high_nonce = False  # True once we've seen nonce >= 0xFF000000

    def _generation_from_nonce(self, nonce_32: int) -> int:
        """
        Compute generation from 32-bit nonce (read-only; does not mutate state).
        """
        msb = (nonce_32 >> 24) & 0xFF
        if self._wrap_count > 0:
            return self._wrap_count * 256 + msb
        if self._seen_high_nonce and msb == 0:
            return 256
        return msb

    def _apply_nonce_seen(self, nonce_32: int) -> None:
        """Update wrap state after successful decryption."""
        if nonce_32 >= 0xFF000000:
            self._seen_high_nonce = True
        if self._seen_high_nonce and ((nonce_32 >> 24) & 0xFF) == 0:
            self._wrap_count += 1
            self._seen_high_nonce = False

    def decrypt(self, protocol_frame: bytes) -> bytes:
        """
        Parse footer, get key for generation (from nonce MSB, with wrap), verify tag, decrypt.

        Args:
            protocol_frame (bytes): Full DAVE protocol frame (ciphertext + footer).

        Returns:
            bytes: Decrypted encoded frame.

        Raises:
            DecryptionError: On nonce reuse or GCM verification failure.
        """
        if len(protocol_frame) == 3 and protocol_frame == SILENCE_PACKET:
            return protocol_frame
        if self._passthrough and not protocol_frame_check(protocol_frame):
            return protocol_frame
        suppl, interleaved_end = _parse_supplemental_from_tail(protocol_frame)
        interleaved = protocol_frame[:interleaved_end]
        if (self._sender_user_id, suppl.nonce_32) in self._used_nonces:
            raise DecryptionError("Nonce reuse")
        msb = (suppl.nonce_32 >> 24) & 0xFF
        generation = self._generation_from_nonce(suppl.nonce_32)
        try:
            key = self._ratchet.get_key_for_generation(generation)
            plain = decrypt_interleaved(
                key,
                suppl.nonce_32,
                interleaved,
                suppl.tag_8,
                suppl.unencrypted_ranges,
            )
        except (DecryptionError, ValueError):
            # Out-of-order: late frame from previous epoch (e.g. nonce 0xFF... after wrap)
            if self._wrap_count > 0 and msb == 255:
                alt_generation = (self._wrap_count - 1) * 256 + 255
                try:
                    key = self._ratchet.get_key_for_generation(alt_generation)
                    plain = decrypt_interleaved(
                        key,
                        suppl.nonce_32,
                        interleaved,
                        suppl.tag_8,
                        suppl.unencrypted_ranges,
                    )
                except (DecryptionError, ValueError):
                    raise
            else:
                raise
        self._apply_nonce_seen(suppl.nonce_32)
        self._used_nonces.add((self._sender_user_id, suppl.nonce_32))
        return plain


def protocol_frame_check(frame: bytes) -> bool:
    """
    Check if frame passes full DAVE protocol structure per protocol.md.

    Validates: minimum size, magic 0xFAFA, supplemental size, ULEB128 nonce,
    ULEB128 unencrypted ranges (ordered, distinct, non-overlapping, within bounds).

    Used by passthrough logic to detect DAVE frames.

    Args:
        frame (bytes): Potential protocol frame.

    Returns:
        bool: True if frame passes all checks.
    """
    if len(frame) < MIN_SUPPLEMENTAL:
        return False
    if frame[-2:] != DAVE_MAGIC:
        return False
    suppl_size = frame[-3]
    if suppl_size < 11 or suppl_size >= len(frame):
        return False
    suppl_content_start = len(frame) - suppl_size
    if suppl_content_start < 0:
        return False
    body = frame[suppl_content_start : len(frame) - 3]
    if len(body) < 8:
        return False
    try:
        offset = 8
        nonce_32, offset = uleb128_decode(body, offset)
        if nonce_32 > 0xFFFFFFFF:
            return False
        interleaved_len = suppl_content_start
        prev_end = 0
        while offset < len(body):
            off_val, offset = uleb128_decode(body, offset)
            if offset > len(body):
                return False
            len_val, offset = uleb128_decode(body, offset)
            if off_val < prev_end:
                return False
            if off_val + len_val > interleaved_len:
                return False
            prev_end = off_val + len_val
    except ValueError:
        return False
    return True
