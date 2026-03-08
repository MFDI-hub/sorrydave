# Media

Frame-level **encryption** and **decryption** with **codec-aware** unencrypted ranges and the **DAVE protocol footer**. The encryptor and decryptor use a **KeyRatchet** (per-sender, per-epoch) and 32-bit truncated nonces; the footer carries the GCM tag, nonce, unencrypted ranges (ULEB128), size byte, and magic `0xFAFA`.

---

## get_unencrypted_ranges

```python
get_unencrypted_ranges(frame: bytes, codec: str) -> list[UnencryptedRange]
```

Returns the list of byte ranges that must remain **plaintext** for the given codec. Used by `FrameEncryptor` and `FrameDecryptor`; you can call it directly to inspect which parts of a frame are left unencrypted.

- **frame**: Raw encoded frame (e.g. OPUS, VP8, H264).
- **codec**: Codec name; case-insensitive. Supported: `"OPUS"`, `"VP9"`, `"VP8"`, `"H264"` / `"H.264"`, `"H265"` / `"HEVC"`, `"AV1"`. Unknown → empty list (full frame encrypted).
- **Returns**: List of `UnencryptedRange(offset, length)`. May be empty (OPUS, VP9, unknown).

See [Codec details](#codec-details) for per-codec behavior.

---

## Frame layout

Each **protocol frame** (output of encrypt, input of decrypt) has:

1. **Payload**: Interleaved plaintext ranges (codec headers) and ciphertext (encrypted ranges), as computed by `get_unencrypted_ranges`.
2. **Supplemental footer**: Appended at the end; see [Supplemental footer layout](#supplemental-footer-layout) below.

For a diagram of the footer structure, see [Concepts → Frame layout](../concepts.md#frame-layout).

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

- Unencrypted ranges are computed by `get_unencrypted_ranges(frame, codec)` (see [Codec details](#codec-details)).
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

## Codec details

Behavior of `get_unencrypted_ranges(frame, codec)` per codec:

| Codec | Unencrypted part | Byte-level detail |
|-------|------------------|-------------------|
| **OPUS**, **VP9** | None | Entire frame encrypted. No headers left plaintext. |
| **VP8** | First 1 or 10 bytes | **Delta frame** (P bit = 1 in first byte): 1 byte (frame header). **Key frame** (P bit = 0): 10 bytes (frame header). LSB of first byte is the P bit. |
| **H264** | 1-byte NAL header per non-VCL NAL | **VCL NALs** (types 1–5): encrypted. **Non-VCL NALs** (e.g. SPS, PPS, SEI): only the 1-byte NAL type header at each NAL start is plaintext. Annex B start codes (`0x000001` / `0x00000001`); 3-byte in plaintext sections expanded to 4-byte by encryptor. |
| **H265/HEVC** | 2-byte NAL header per non-VCL NAL | **VCL NALs**: encrypted. **Non-VCL NALs** (type ≥ 32): 2-byte NAL header at each NAL start is plaintext. Annex B start codes; same 3→4 byte expansion. |
| **AV1** | OBU header + optional extension + optional size | Per **OBU**: 1-byte header; optional extension byte; optional LEB128 size. **Payload** of the OBU is encrypted. OBU types **2** (temporal delimiter), **8** (tile list), **15** (padding) are skipped (no payload). |
| **Unknown** | None | Empty list; full frame is encrypted. |

---

## Supplemental footer layout

At the end of every protocol frame:

1. **Supplemental body**: 8-byte GCM tag + ULEB128(nonce_32) + for each unencrypted range: ULEB128(offset), ULEB128(length).
2. **Supplemental size**: 1 byte = length of (body + size byte + 2 magic bytes).
3. **Magic**: 2 bytes `0xFAFA`.

Minimum footer size: 8 + 1 + 0 + 1 + 2 = 12 bytes. Maximum supplemental size: 255 bytes.

---

## protocol_frame_check

```python
protocol_frame_check(frame: bytes) -> bool
```

**Location:** `sorrydave.media.transform.protocol_frame_check`

- **frame**: Byte string (e.g. received media packet).
- **Returns**: `True` if the frame has at least minimum length, ends with the 2-byte magic `0xFAFA`, and the supplemental size byte (before the magic) is in valid range (so the footer looks like a DAVE protocol frame). `False` otherwise.
- **Note:** Does not fully parse or verify the supplemental body (tag, nonce, ranges). Use for quick detection of DAVE frames in passthrough logic (e.g. skip decryption for non-DAVE packets).

---

## Cipher and ULEB128 (low-level)

- **sorrydave.crypto.cipher**: `encrypt_interleaved`, `decrypt_interleaved`, `uleb128_encode`, `uleb128_decode`, `expand_nonce_96`, `DAVE_MAGIC`, `GCM_TAG_LENGTH`, `NONCE_LENGTH_BYTES`.
- **sorrydave.crypto.ratchet**: `KeyRatchet(base_secret, retention_seconds, max_forward_gap)`, `get_key_for_generation(generation)`.

These are used by `FrameEncryptor` / `FrameDecryptor`; most users only need the session’s `get_encryptor()` and `get_decryptor(sender_id)`.

---

## API reference (auto-generated)

::: sorrydave.media.codecs.get_unencrypted_ranges
::: sorrydave.media.transform.FrameEncryptor
::: sorrydave.media.transform.FrameDecryptor
