"""
ULEB128 encoding/decoding and truncated AES128-GCM for DAVE media frames.
"""

from pydave.exceptions import DecryptionError
from pydave.types import UnencryptedRange

# DAVE protocol constants
DAVE_MAGIC = bytes((0xFA, 0xFA))
GCM_TAG_LENGTH = 8
NONCE_LENGTH_BYTES = 4  # 32-bit truncated nonce
FULL_NONCE_LENGTH = 12  # 96-bit for AES-GCM


def uleb128_encode(value: int) -> bytes:
    """
    Encode nonnegative integer as ULEB128 (unsigned little-endian base 128).

    Args:
        value (int): Nonnegative integer to encode.

    Returns:
        bytes: ULEB128-encoded bytes.

    Raises:
        ValueError: If value is negative.
    """
    if value < 0:
        raise ValueError("ULEB128 requires nonnegative integer")
    buf = []
    while value >= 0x80:
        buf.append(0x80 | (value & 0x7F))
        value >>= 7
    buf.append(value & 0x7F)
    return bytes(buf)


def uleb128_decode(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode one ULEB128 value from data starting at offset.

    Args:
        data (bytes): Buffer containing ULEB128-encoded value.
        offset (int): Start index. Defaults to 0.

    Returns:
        tuple[int, int]: (decoded value, new_offset past the value).

    Raises:
        ValueError: On invalid encoding, overflow (e.g. > 64 bits), or truncated data.
    """
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if byte < 0x80:
            return result, pos
        shift += 7
        if shift >= 64:  # prevent unbounded
            raise ValueError("ULEB128 overflow")
    raise ValueError("ULEB128 truncated")


def expand_nonce_96(truncated_nonce_32: int) -> bytes:
    """
    Expand 32-bit truncated nonce to 96-bit for AES-GCM.

    Full nonce = 8 zero bytes || 4-byte truncated nonce (little-endian).

    Args:
        truncated_nonce_32 (int): 32-bit nonce value.

    Returns:
        bytes: 12-byte (96-bit) nonce for AES-GCM.

    Raises:
        ValueError: If value does not fit in 32 bits.
    """
    if not 0 <= truncated_nonce_32 <= 0xFFFFFFFF:
        raise ValueError("Nonce must fit in 32 bits")
    return b"\x00" * 8 + truncated_nonce_32.to_bytes(4, "little")


def _encrypt_gcm(key: bytes, nonce_12: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt with AES128-GCM.

    Args:
        key (bytes): 16-byte AES key.
        nonce_12 (bytes): 12-byte nonce.
        plaintext (bytes): Data to encrypt.
        aad (bytes): Additional authenticated data.

    Returns:
        tuple[bytes, bytes]: (ciphertext, 8-byte tag).
    """
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_12, mac_len=GCM_TAG_LENGTH)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def _decrypt_gcm(key: bytes, nonce_12: bytes, ciphertext: bytes, tag_8: bytes, aad: bytes) -> bytes:
    """
    Decrypt with AES128-GCM (8-byte tag).

    Args:
        key (bytes): 16-byte AES key.
        nonce_12 (bytes): 12-byte nonce.
        ciphertext (bytes): Encrypted data.
        tag_8 (bytes): 8-byte GCM authentication tag.
        aad (bytes): Additional authenticated data.

    Returns:
        bytes: Decrypted plaintext.

    Raises:
        DecryptionError: On invalid tag length or GCM verification failure.
    """
    from Crypto.Cipher import AES

    if len(tag_8) != GCM_TAG_LENGTH:
        raise DecryptionError("Invalid tag length")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_12, mac_len=GCM_TAG_LENGTH)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag_8)
    except (ValueError, KeyError) as e:
        raise DecryptionError("GCM verification failed") from e


def encrypt_interleaved(
    key: bytes,
    nonce_32: int,
    frame: bytes,
    unencrypted_ranges: list[UnencryptedRange],
) -> tuple[bytes, bytes]:
    """
    Encrypt frame with interleaved unencrypted ranges.

    Plaintext to encrypt is the concatenation of encrypted-range bytes (in order).
    AAD is the concatenation of unencrypted-range bytes (in order).

    Args:
        key (bytes): 16-byte AES key.
        nonce_32 (int): 32-bit truncated nonce.
        frame (bytes): Full frame bytes.
        unencrypted_ranges (list[UnencryptedRange]): Ranges to leave in plaintext.

    Returns:
        tuple[bytes, bytes]: (interleaved frame with ciphertext in encrypted ranges, 8-byte tag).
    """
    if not unencrypted_ranges:
        # Full frame encrypted
        aad = b""
        plaintext = frame
        nonce_12 = expand_nonce_96(nonce_32)
        ciphertext, tag_8 = _encrypt_gcm(key, nonce_12, plaintext, aad)
        return ciphertext, tag_8

    # Build plaintext (encrypted parts) and AAD (unencrypted parts)
    encrypted_parts = []
    aad_parts = []
    last_end = 0
    for r in sorted(unencrypted_ranges, key=lambda x: x.offset):
        if r.offset > last_end:
            encrypted_parts.append(frame[last_end : r.offset])
        aad_parts.append(frame[r.offset : r.offset + r.length])
        last_end = r.offset + r.length
    if last_end < len(frame):
        encrypted_parts.append(frame[last_end:])
    plaintext = b"".join(encrypted_parts)
    aad = b"".join(aad_parts)

    nonce_12 = expand_nonce_96(nonce_32)
    ciphertext_block, tag_8 = _encrypt_gcm(key, nonce_12, plaintext, aad)

    # Interleave: place ciphertext back into encrypted ranges, keep unencrypted in place
    out = bytearray()
    ct_offset = 0
    last_end = 0
    for r in sorted(unencrypted_ranges, key=lambda x: x.offset):
        if r.offset > last_end:
            n = r.offset - last_end
            out.extend(ciphertext_block[ct_offset : ct_offset + n])
            ct_offset += n
        out.extend(frame[r.offset : r.offset + r.length])
        last_end = r.offset + r.length
    if last_end < len(frame):
        out.extend(ciphertext_block[ct_offset:])
    return bytes(out), tag_8


def decrypt_interleaved(
    key: bytes,
    nonce_32: int,
    interleaved: bytes,
    tag_8: bytes,
    unencrypted_ranges: list[UnencryptedRange],
) -> bytes:
    """
    Decrypt interleaved frame.

    Reconstructs AAD and ciphertext from ranges and verifies the tag.

    Args:
        key (bytes): 16-byte AES key.
        nonce_32 (int): 32-bit truncated nonce.
        interleaved (bytes): Frame with ciphertext in encrypted ranges.
        tag_8 (bytes): 8-byte GCM tag.
        unencrypted_ranges (list[UnencryptedRange]): Same ranges used during encrypt.

    Returns:
        bytes: Decrypted frame (plaintext reconstructed with unencrypted ranges in place).

    Raises:
        DecryptionError: On tag mismatch or invalid data.
    """
    if not unencrypted_ranges:
        nonce_12 = expand_nonce_96(nonce_32)
        return _decrypt_gcm(key, nonce_12, interleaved, tag_8, b"")

    encrypted_parts = []
    aad_parts = []
    last_end = 0
    for r in sorted(unencrypted_ranges, key=lambda x: x.offset):
        if r.offset > last_end:
            encrypted_parts.append(interleaved[last_end : r.offset])
        aad_parts.append(interleaved[r.offset : r.offset + r.length])
        last_end = r.offset + r.length
    if last_end < len(interleaved):
        encrypted_parts.append(interleaved[last_end:])
    ciphertext_block = b"".join(encrypted_parts)
    aad = b"".join(aad_parts)

    nonce_12 = expand_nonce_96(nonce_32)
    plaintext_block = _decrypt_gcm(key, nonce_12, ciphertext_block, tag_8, aad)

    # Reconstruct original frame by interleaving decrypted segments back
    out = bytearray()
    pt_offset = 0
    last_end = 0
    for r in sorted(unencrypted_ranges, key=lambda x: x.offset):
        if r.offset > last_end:
            n = r.offset - last_end
            out.extend(plaintext_block[pt_offset : pt_offset + n])
            pt_offset += n
        out.extend(interleaved[r.offset : r.offset + r.length])
        last_end = r.offset + r.length
    if last_end < len(interleaved):
        out.extend(plaintext_block[pt_offset:])
    return bytes(out)
