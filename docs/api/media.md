# Media

Frame-level **encryption** and **decryption** with **codec-aware** unencrypted ranges and the **DAVE protocol footer**. The encryptor and decryptor use a **KeyRatchet** (per-sender, per-epoch) and 32-bit truncated nonces; the footer carries the GCM tag, nonce, unencrypted ranges (ULEB128), size byte, and magic `0xFAFA`.

---

## FrameEncryptor

Encrypts **encoded** media frames (output of your codec encoder). Leaves codec-defined ranges in plaintext and appends the DAVE supplemental footer.

### Constructor

```python
FrameEncryptor(sender_user_id: int, ratchet: KeyRatchet, nonce_supplier: Callable[[], int] | None = None)
```

- **sender_user_id**: Sender user ID (e.g. Discord snowflake).
- **ratchet**: KeyRatchet for the current sender/epoch (from session’s send ratchet).
- **nonce_supplier**: Optional callable that returns the next nonce (for tests). If not set, a monotonic counter is used (wraps at 2^32; generation advances with ratchet).

### encrypt

```python
encrypt(encoded_frame: bytes, codec: str) -> bytes
```

- **encoded_frame**: Raw encoded frame from your codec (OPUS, VP8, VP9, H264, H265, AV1).
- **codec**: Codec name; case-insensitive. Supported: `"OPUS"`, `"VP9"`, `"VP8"`, `"H264"` / `"H.264"`, `"H265"` / `"H265/HEVC"` / `"HEVC"`, `"AV1"`. Unknown codecs → full frame encrypted.
- **Returns**: Protocol frame (interleaved ciphertext + supplemental footer: tag, ULEB128 nonce, ULEB128 offset/length pairs, 1-byte supplemental size, 2-byte magic `0xFAFA`).
- **Raises**: **DecryptionError** if supplemental would exceed 255 bytes or (for H264/H265) H26x start code appears in ciphertext/supplemental after max retries.

**Behavior**

- Unencrypted ranges are computed by `get_unencrypted_ranges(frame, codec)` (see [Codecs](#codecs)).
- For H264/H265, 3-byte start codes in unencrypted sections are expanded to 4-byte; encryption is retried up to 10 times if a start code appears in ciphertext or footer.
- Generation is `(nonce >> 24) & 0xFF`; key is `ratchet.get_key_for_generation(generation)`.
- AAD for GCM is the concatenation of unencrypted range bytes; ciphertext is the concatenation of encrypted-range bytes, then interleaved back with plaintext ranges.

---

## FrameDecryptor

Decrypts **protocol** frames (ciphertext + DAVE footer). Parses footer, looks up key by generation, verifies GCM tag, and rejects nonce reuse.

### Constructor

```python
FrameDecryptor(sender_user_id: int, ratchet: KeyRatchet)
```

- **sender_user_id**: Sender user ID (for nonce-reuse tracking).
- **ratchet**: KeyRatchet for this sender (from session’s receive ratchets).

### decrypt

```python
decrypt(protocol_frame: bytes) -> bytes
```

- **protocol_frame**: Full DAVE protocol frame (interleaved ciphertext + supplemental block ending with size byte and `0xFAFA`).
- **Returns**: Decrypted encoded frame (plaintext).
- **Raises**: **DecryptionError** on nonce reuse, GCM verification failure, or invalid/malformed supplemental (e.g. wrong magic, bad size, truncated data).

**Behavior**

- Supplemental is parsed from the end: magic, size byte, then tag + ULEB128 nonce + ULEB128 offset/length pairs.
- Generation = `(nonce_32 >> 24) & 0xFF`; key = `ratchet.get_key_for_generation(generation)`.
- Each `(sender_user_id, nonce_32)` is recorded; reuse raises DecryptionError.

---

## Codecs (unencrypted ranges)

Defined in `sorrydave.media.codecs.get_unencrypted_ranges(frame, codec)`:

| Codec | Unencrypted ranges |
|-------|--------------------|
| OPUS, VP9 | None (entire frame encrypted). |
| VP8 | First 1 byte (delta frame) or first 10 bytes (key frame), per P bit (LSB of first byte). |
| H264 | For each non-VCL NAL (type not in 1–5), 1-byte NAL header at NAL start. VCL encrypted. Annex B start codes. |
| H265/HEVC | For each non-VCL NAL (type ≥ 32), 2-byte NAL header. VCL encrypted. Annex B start codes. |
| AV1 | For each OBU: header byte, optional extension byte, optional LEB128 size; payload encrypted. OBU types 2, 8, 15 (temporal delimiter, tile list, padding) are skipped. |
| Unknown | Empty list → full frame encrypted. |

---

## Supplemental footer layout

At the end of every protocol frame:

1. **Supplemental body**: 8-byte GCM tag + ULEB128(nonce_32) + for each unencrypted range: ULEB128(offset), ULEB128(length).
2. **Supplemental size**: 1 byte = length of (body + size byte + 2 magic bytes).
3. **Magic**: 2 bytes `0xFAFA`.

Minimum footer size: 8 + 1 + 0 + 1 + 2 = 12 bytes. Maximum supplemental size: 255 bytes.

---

## Helper: protocol_frame_check

```python
protocol_frame_check(frame: bytes) -> bool
```

Returns True if the frame has at least minimum length, ends with `0xFAFA`, and the supplemental size byte is in valid range. Used by passthrough logic to detect DAVE frames. Does not fully parse or verify the supplemental body.

---

## Cipher and ULEB128 (low-level)

- **sorrydave.crypto.cipher**: `encrypt_interleaved`, `decrypt_interleaved`, `uleb128_encode`, `uleb128_decode`, `expand_nonce_96`, `DAVE_MAGIC`, `GCM_TAG_LENGTH`, `NONCE_LENGTH_BYTES`.
- **sorrydave.crypto.ratchet**: `KeyRatchet(base_secret, retention_seconds, max_forward_gap)`, `get_key_for_generation(generation)`.

These are used by `FrameEncryptor` / `FrameDecryptor`; most users only need the session’s `get_encryptor()` and `get_decryptor(sender_id)`.

---

## API reference (auto-generated)

::: sorrydave.media.transform.FrameEncryptor
::: sorrydave.media.transform.FrameDecryptor
