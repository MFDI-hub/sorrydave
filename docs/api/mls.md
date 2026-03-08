# MLS & opcodes

This module covers **Voice Gateway opcode** parsing and building (opcodes 22, 25–31) and the **MLS group state** helpers used by `DaveSession`. All functions consume or produce **bytes**; no I/O is performed.

---

## Opcode constants

Defined in `sorrydave.mls.opcodes`:

| Constant | Value | Description |
|----------|--------|-------------|
| `OPCODE_EXECUTE_TRANSITION` | 22 | Execute Transition (JSON). |
| `OPCODE_EXTERNAL_SENDER_PACKAGE` | 25 | External Sender Package (binary). |
| `OPCODE_KEY_PACKAGE` | 26 | Key Package (binary). |
| `OPCODE_PROPOSALS` | 27 | Proposals (binary). |
| `OPCODE_COMMIT_WELCOME` | 28 | Commit / Welcome (binary). |
| `OPCODE_ANNOUNCE_COMMIT` | 29 | Announce Commit (binary). |
| `OPCODE_WELCOME` | 30 | Welcome (binary). |
| `OPCODE_INVALID_COMMIT_WELCOME` | 31 | Invalid Commit/Welcome (JSON). |

---

## Binary opcodes (25–30)

### Opcode 25: External Sender Package

- **Parse**: `parse_external_sender_package(data: bytes) -> ExternalSenderPackage`
  - **data**: Full opcode 25 payload (2-byte sequence, 1-byte opcode, then body).
  - **Returns**: `ExternalSenderPackage(sequence_number, signature_key, credential_type, identity)`.
  - **Raises**: `ValueError` if payload too short or opcode is not 25.

**ExternalSenderPackage** (dataclass):

- `sequence_number` (int)
- `signature_key` (bytes) — signature public key (opaque&lt;V&gt;)
- `credential_type` (int) — e.g. BASIC
- `identity` (bytes) — identity bytes (e.g. user ID)

---

### Opcode 26: Key Package

- **Build**: `build_key_package_message(key_package_bytes: bytes) -> bytes`
  - **key_package_bytes**: Serialized MLS KeyPackage.
  - **Returns**: 1-byte opcode (26) concatenated with key package bytes. This is the payload to send as opcode 26.

---

### Opcode 27: Proposals

- **Parse**: `parse_proposals(data: bytes) -> ProposalsMessage`
  - **data**: Full opcode 27 payload.
  - **Returns**: `ProposalsMessage(sequence_number, operation_type, proposal_messages=None, proposal_refs=None)`.
  - **operation_type**: 0 = append (list of proposal messages), 1 = revoke (list of proposal refs).
  - **Raises**: `ValueError` if payload too short, wrong opcode, or unknown operation type.

**ProposalsMessage** (dataclass):

- `sequence_number` (int)
- `operation_type` (int) — 0 append, 1 revoke
- `proposal_messages` (list[bytes] | None) — for append
- `proposal_refs` (list[bytes] | None) — for revoke

---

### Opcode 28: Commit / Welcome

- **Build**: `build_commit_welcome(commit_message: bytes, welcome_message: bytes | None) -> bytes`
  - **commit_message**: Serialized MLS commit (MLS Plaintext).
  - **welcome_message**: Optional serialized Welcome (not wrapped in MLSMessage per DAVE).
  - **Returns**: 1-byte opcode (28) + varint-length-prefixed commit + optional welcome bytes. This is the payload to send as opcode 28.

---

### Opcode 29: Announce Commit

- **Parse**: `parse_announce_commit(data: bytes) -> tuple[int, bytes]`
  - **data**: Full opcode 29 payload (sequence, opcode, transition_id, commit).
  - **Returns**: `(transition_id, commit_message_bytes)`.
  - **Raises**: `ValueError` if payload too short or opcode is not 29.

---

### Opcode 30: Welcome

- **Parse**: `parse_welcome_message(data: bytes) -> tuple[int, bytes]`
  - **data**: Full opcode 30 payload.
  - **Returns**: `(transition_id, welcome_bytes)`.
  - **Raises**: `ValueError` if payload too short or opcode is not 30.

---

## JSON opcodes (22, 31)

### Opcode 22: Execute Transition

- **Parse**: `parse_execute_transition(payload: bytes) -> int`
  - **payload**: UTF-8 JSON, e.g. `{"op": 22, "d": {"transition_id": 10}}`.
  - **Returns**: `transition_id` (int, 0–65535).
  - **Raises**: `ValueError` if JSON invalid, missing `d.transition_id`, or value out of uint16 range.

---

### Opcode 31: Invalid Commit/Welcome

- **Build**: `build_invalid_commit_welcome(transition_id: int) -> bytes`
  - **transition_id**: Transition ID (0–65535).
  - **Returns**: UTF-8 JSON payload for opcode 31, e.g. `{"op":31,"d":{"transition_id":10}}`.
  - **Raises**: `ValueError` if transition_id not in uint16 range.

Use after catching **InvalidCommitError**; then call `session.prepare_epoch(1)` and send the returned key package as opcode 26.

---

## Group state (sorrydave.mls.group_state)

These functions are used internally by `DaveSession` but can be used for custom flows.

### get_dave_crypto_provider

```python
get_dave_crypto_provider() -> DefaultCryptoProvider
```

Returns an rfc9420 `DefaultCryptoProvider` for DAVE’s MLS ciphersuite (ID 2: DHKEMP256_AES128GCM_SHA256_P256).

---

### create_key_package

```python
create_key_package(user_id: int, crypto: DefaultCryptoProvider | None = None) -> tuple[bytes, bytes, bytes]
```

Creates a KeyPackage for the given user_id (identity = 8-byte big-endian user_id). Returns `(key_package_serialized, hpke_private_key, signing_key_der)`. **Raises** `ValueError` if ciphersuite is unknown.

---

### create_group

```python
create_group(group_id: bytes, key_package_bytes: bytes, crypto: DefaultCryptoProvider | None = None) -> Group
```

Creates a new MLS group with a single member (the given key package). Returns rfc9420 `Group`.

---

### join_from_welcome

```python
join_from_welcome(welcome_bytes: bytes, hpke_private_key: bytes, crypto: DefaultCryptoProvider | None = None) -> Group
```

Joins a group from a Welcome message. **hpke_private_key** is the HPKE private key from the KeyPackage that was added.

---

### export_sender_base_secret

```python
export_sender_base_secret(group: Group, sender_user_id: int) -> bytes
```

Exports the 16-byte sender base secret via MLS Exporter: label `"Discord Secure Frames v0"`, context = 8-byte little-endian sender_user_id. Used to build `KeyRatchet` for send/receive.

---

### apply_commit

```python
apply_commit(group: Group, commit_mls_plaintext_bytes: bytes, sender_leaf_index: int) -> None
```

Applies a received commit to the group. **Raises** **InvalidCommitError** on failure.

---

### create_commit_and_welcome

```python
create_commit_and_welcome(group: Group, signing_key_der: bytes) -> tuple[bytes, list[bytes]]
```

Creates commit and optional welcome messages. Returns `(serialized_commit_plaintext, list_of_serialized_welcome_bytes)`.

---

### create_remove_proposal_for_self

```python
create_remove_proposal_for_self(group: Group, signing_key_der: bytes) -> bytes
```

Returns serialized MLS Plaintext Remove proposal for the local member (self-remove). Send via opcode 27.

---

### create_update_proposal

```python
create_update_proposal(group: Group, signing_key_der: bytes, user_id: int, crypto: DefaultCryptoProvider | None = None) -> bytes
```

Returns serialized MLS Plaintext Update proposal to refresh the local member’s leaf keys. Send via opcode 27. **Raises** `ValueError` if ciphersuite unknown.

---

### process_proposal

```python
process_proposal(group: Group, proposal_mls_plaintext_bytes: bytes, sender_leaf_index: int, sender_type: int = 1) -> None
```

Processes a single proposal (e.g. Add/Remove from external sender). **sender_type**: 1 = MEMBER, 2 = EXTERNAL.

---

## Constants (group_state)

- **DAVE_MLS_CIPHERSUITE_ID**: 2
- **EXPORTER_LABEL**: `b"Discord Secure Frames v0"`
- **EXPORTER_LENGTH**: 16

---

## API reference (auto-generated)

::: sorrydave.mls
