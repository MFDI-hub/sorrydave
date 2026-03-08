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

## Other Voice Gateway opcodes

These parse/build functions handle JSON or binary payloads used by the Voice Gateway for protocol handshake and lifecycle. Your app typically calls them when dispatching gateway messages.

### build_identify

```python
build_identify(max_dave_protocol_version: int = 1, **d_extra: object) -> bytes
```

Builds the **Identify** message payload (UTF-8 JSON) to send when connecting to the Voice Gateway. Includes `d.dave_protocol_version` (or similar) and any extra keys in `d`.

- **max_dave_protocol_version**: Maximum DAVE protocol version the client supports (default 1).
- **d_extra**: Optional key-value pairs merged into the `d` object.
- **Returns**: Bytes to send as the identify payload (e.g. over WebSocket).

**When to call:** At connection start, before the gateway sends select_protocol_ack or prepare_epoch.

---

### parse_select_protocol_ack

```python
parse_select_protocol_ack(payload: bytes) -> int
```

Parses the **select_protocol_ack** response (UTF-8 JSON) from the gateway. Returns the negotiated DAVE protocol version.

- **payload**: Raw bytes of the ack message.
- **Returns**: Protocol version (int).
- **Raises:** `ValueError` if JSON invalid or version missing.

**When to call:** After sending identify; use the returned version and then call `session.prepare_epoch(1)` when the gateway signals to prepare epoch.

---

### parse_clients_connect

```python
parse_clients_connect(payload: bytes) -> list[str]
```

Parses a **clients_connect**-style payload (UTF-8 JSON) listing client/user identifiers that joined.

- **payload**: Raw bytes of the message.
- **Returns**: List of client IDs (strings).

**When to call:** When the gateway notifies that clients have connected; use for UI or to know who may send media.

---

### parse_client_disconnect

```python
parse_client_disconnect(payload: bytes) -> str
```

Parses a **client_disconnect** payload (UTF-8 JSON) and returns the disconnected client ID.

- **payload**: Raw bytes of the message.
- **Returns**: Client ID (string).

**When to call:** When the gateway notifies that a client disconnected.

---

### parse_prepare_transition

```python
parse_prepare_transition(payload: bytes) -> tuple[int, int]
```

Parses a **prepare_transition** payload (UTF-8 JSON). Returns the transition ID and epoch (or similar) the gateway is preparing.

- **payload**: Raw bytes of the message (UTF-8 JSON with "d.protocol_version" and "d.transition_id").
- **Returns**: `(protocol_version, transition_id)`. transition_id 0 means execute immediately.
- **Raises:** `ValueError` if JSON invalid, fields missing, or transition_id not in uint16 range.

**When to call:** When the gateway signals that a transition is being prepared (before opcode 22).

---

### build_ready_for_transition

```python
build_ready_for_transition(transition_id: int) -> bytes
```

Builds the **ready_for_transition** payload (UTF-8 JSON) to send to the gateway to acknowledge readiness for the given transition.

- **transition_id**: Transition ID (0–65535).
- **Returns**: Bytes to send as the ready payload.

**When to call:** After processing commit/welcome and before or when the gateway sends opcode 22; confirms the client is ready to execute the transition.

---

### parse_prepare_epoch

```python
parse_prepare_epoch(payload: bytes) -> tuple[int, int]
```

Parses a **prepare_epoch** payload (UTF-8 JSON) from the gateway. Returns the epoch ID and optional protocol version or similar.

- **payload**: Raw bytes of the message (UTF-8 JSON with "d.protocol_version" and "d.epoch").
- **Returns**: `(protocol_version, epoch)`. epoch 1 means new MLS group to be created.
- **Raises:** `ValueError` if JSON invalid or protocol_version/epoch missing or not integers.

**When to call:** When the gateway tells the client to prepare an epoch; use the epoch (e.g. 1) to call `session.prepare_epoch(epoch_id)`.

---

## Group state (sorrydave.mls.group_state)

These functions are used internally by `DaveSession` but can be used for custom flows. Short reference:

| Function | Used by DaveSession when … |
|----------|----------------------------|
| `get_dave_crypto_provider` | Creating key packages and groups; provides rfc9420 crypto for DAVE ciphersuite. |
| `create_key_package` | `prepare_epoch(1)` to build the key package and store HPKE/signing keys. |
| `create_group` | `handle_external_sender_package` (with key package ready) to create the initial group. |
| `join_from_welcome` | `handle_welcome` to join the group from a Welcome message. |
| `export_sender_base_secret` | Refreshing send/receive ratchets (per-sender base secret for KeyRatchet). |
| `apply_commit` | `handle_commit` to apply an announced commit to the group. |
| `process_proposal` | `handle_proposals` to apply each proposal before creating a commit. |
| `create_commit_and_welcome` | `handle_proposals` to build the opcode 28 payload. |
| `create_remove_proposal_for_self` | `leave_group` to build the Remove proposal for the local member. |
| `create_update_proposal` | Optional; to refresh the local member’s leaf (not called by default session flow). |
| `validate_group_external_sender` | Validating the external sender against the group. |
| `get_external_senders_from_group` | Reading external sender data from the group. |

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
