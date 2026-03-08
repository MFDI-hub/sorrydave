# Types & exceptions

Configuration and protocol data types used across sorrydave, and DAVE-specific exceptions. All are in the top-level `sorrydave` package or in `sorrydave.types` / `sorrydave.exceptions`.

---

## Exceptions

All DAVE protocol errors inherit from **DaveProtocolError** so you can catch a single base class.

### DaveProtocolError

Base exception for DAVE protocol errors. Catch this to handle any protocol-level failure from the library.

```python
try:
    session.handle_commit(transition_id, commit_bytes)
except sorrydave.DaveProtocolError as e:
    # Covers InvalidCommitError and other protocol errors
    ...
```

---

### DecryptionError (DaveProtocolError)

Raised when decryption fails: GCM tag mismatch, nonce reuse, invalid supplemental, or key mismatch.

- **When**: Typically from `FrameDecryptor.decrypt()`, or from low-level `decrypt_interleaved` / GCM verification.
- **Action**: Fail closed: drop the frame and do not use its content. Do not retry with the same frame.

```python
from sorrydave import DecryptionError

try:
    plain = decryptor.decrypt(protocol_frame)
except DecryptionError:
    # Log and drop frame
    pass
```

---

### InvalidCommitError (DaveProtocolError)

Raised when a commit or welcome cannot be processed (e.g. no group, or rfc9420 reject).

- **When**: From `session.handle_commit()` (or from `apply_commit()` in group_state).
- **Action**: Send **opcode 31** with `build_invalid_commit_welcome(transition_id)`, then call `session.prepare_epoch(1)` and send the returned key package as **opcode 26**.

```python
from sorrydave import InvalidCommitError
from sorrydave.mls import build_invalid_commit_welcome

try:
    session.handle_commit(transition_id, commit_bytes)
except InvalidCommitError:
    send_opcode_31(build_invalid_commit_welcome(transition_id))
    kp = session.prepare_epoch(1)
    if kp:
        send_opcode_26(kp)
```

---

## Data types (sorrydave.types)

### UnencryptedRange

```python
@dataclass(frozen=True)
class UnencryptedRange:
    offset: int   # Start offset in the frame
    length: int   # Number of bytes in the range
```

Describes a byte range that must remain **plaintext** (e.g. codec headers for SFU routing). Used in `ProtocolSupplementalData` and by the media transform.

---

### ProtocolSupplementalData

```python
@dataclass
class ProtocolSupplementalData:
    tag_8: bytes                    # 8-byte GCM authentication tag
    nonce_32: int                    # 32-bit truncated nonce
    unencrypted_ranges: list[UnencryptedRange]  # Ranges left in plaintext
    supplemental_size: int          # Total supplemental block size in bytes
```

Parsed DAVE protocol footer (supplemental data). Layout: 8-byte tag, ULEB128 nonce, ULEB128 offset/length pairs, 1-byte size, 2-byte magic `0xFAFA`. Returned by the decrypt path when parsing the footer; most users only need the decrypted frame bytes.

---

### DaveConfiguration

```python
@dataclass(frozen=True)
class DaveConfiguration:
    protocol_version: int = 1
    mls_ciphersuite: int = 2       # DHKEMP256_AES128GCM_SHA256_P256
    media_ciphersuite: str = "AES128-GCM"
    ratchet_retention_seconds: int = 10
```

Immutable configuration for DAVE protocol version and ciphersuites. Currently **DaveSession** does not take this type in the constructor (it uses default behavior); it is provided for reference and future use.

---

### IdentityConfig

```python
@dataclass(frozen=True)
class IdentityConfig:
    is_persistent: bool = False
    storage_path: str | None = None
```

Configuration for identity key storage (ephemeral vs persistent). Currently the library does not persist keys; this type is for reference and future use.

---

## Re-exports from sorrydave

The top-level package re-exports:

- **Exceptions**: `DaveProtocolError`, `DecryptionError`, `InvalidCommitError`
- **Types**: `UnencryptedRange`, `ProtocolSupplementalData`, `DaveConfiguration`, `IdentityConfig`
- **Session**: `DaveSession`
- **Media**: `FrameEncryptor`, `FrameDecryptor`
- **Identity**: `generate_fingerprint`, `displayable_code`

Example:

```python
from sorrydave import DaveSession, DecryptionError, InvalidCommitError, generate_fingerprint
```

---

## API reference (auto-generated)

::: sorrydave.exceptions
::: sorrydave.types
