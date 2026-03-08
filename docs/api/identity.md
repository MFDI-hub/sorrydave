# Identity

Identity utilities for **pairwise verification** and **displayable codes**: fingerprint from two users’ public keys and IDs, and encoding of raw bytes as numeric groups (e.g. 45-digit fingerprint, 30-digit epoch authenticator).

---

## generate_fingerprint

```python
generate_fingerprint(local_id: int, local_pub: bytes, remote_id: int, remote_pub: bytes) -> str
```

Produces a **45-digit pairwise verification fingerprint** (9 groups of 5 digits).

- **local_id**, **remote_id**: 64-bit user IDs (e.g. Discord snowflakes).
- **local_pub**, **remote_pub**: Public key bytes (e.g. MLS signature or HPKE public key; must match what the protocol uses for verification).
- **Algorithm**: Builds `bufA = V || PubA || Sa`, `bufB = V || PubB || Sb` where `V` is version (2 zero bytes), `Sa`/`Sb` are 8-byte big-endian user IDs. Sorts the two buffers lexicographically, concatenates, then derives 64 bytes with **scrypt** (N=16384, r=8, p=2, salt from protocol). The result is encoded as 9 groups of 5 digits (see **displayable_code**).
- **Returns**: String of 45 digits (e.g. `"123456789012345678901234567890123456789012345"`). Formatting with spaces (e.g. 9×5) is up to the UI.

Use this so two participants can compare fingerprints out-of-band and confirm they are in the same E2EE session.

---

## displayable_code

```python
displayable_code(data: bytes, total_digits: int, group_size: int = 5) -> str
```

Encodes a byte array as a **displayable numeric code**.

- **data**: Raw bytes to encode.
- **total_digits**: Total number of digits in the output (must be a multiple of `group_size`).
- **group_size**: Digits per group (default 5). Must be &lt; 8 (each group uses `group_size` bytes as big-endian int modulo 10^group_size, zero-padded).
- **Returns**: Single string of digits (e.g. `"1234567890"` for two groups of 5). No spaces; add spaces in UI if desired (e.g. every 5 digits).
- **Raises**: **ValueError** if `total_digits % group_size != 0`, `group_size >= 8`, or `data` is shorter than required.

**Example**: 64-byte fingerprint output → 45 digits = 9×5 → need 9×5 = 45 bytes; scrypt output is 64 bytes, so first 45 bytes are used.

---

## epoch_authenticator_display

```python
epoch_authenticator_display(epoch_authenticator_32_bytes: bytes) -> str
```

Encodes at least the first **30 bytes** of an epoch authenticator (e.g. MLS-exported secret) as a **30-digit** displayable code (6 groups of 5).

- **epoch_authenticator_32_bytes**: At least 30 bytes (e.g. 32-byte export).
- **Returns**: String of 30 digits.
- **Raises**: **ValueError** if input is shorter than 30 bytes.

Use for “epoch authenticity” verification UI when the protocol exposes an epoch authenticator.

---

## Constants (identity)

In `sorrydave.identity`:

- **FINGERPRINT_SALT**: 16-byte salt for scrypt (per protocol).
- **FINGERPRINT_VERSION**: `bytes((0x00, 0x00))`.
- **SCRYPT_N**, **SCRYPT_R**, **SCRYPT_P**, **SCRYPT_DKLEN**: scrypt parameters (e.g. N=16384, r=8, p=2, dkLen=64).
- **PAIRWISE_DIGITS**: 45.
- **PAIRWISE_GROUP_SIZE**: 5.
- **EPOCH_AUTH_DIGITS**: 30.
- **EPOCH_AUTH_GROUP_SIZE**: 5.

---

## API reference (auto-generated)

::: sorrydave.identity.generate_fingerprint
::: sorrydave.identity.displayable_code
