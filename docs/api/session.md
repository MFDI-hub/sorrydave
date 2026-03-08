# Session

The **DaveSession** is the high-level facade for a DAVE media session. It holds MLS group state, per-sender key ratchets, and provides frame encrypt/decrypt. All Voice Gateway opcode handling and media transforms go through the session; it performs no I/O—you pass in bytes and get back bytes.

---

## Class: DaveSession

**Constructor**

```python
DaveSession(local_user_id: int, protocol_version: int = 1)
```

- **local_user_id** (int): Your user identifier (e.g. Discord snowflake, 64-bit). Used in key package identity, exporter context, and encryptor identity.
- **protocol_version** (int): DAVE protocol version; defaults to `1`.

**Internal state (conceptual)**

- MLS group (rfc9420 `Group`), crypto provider, HPKE private key, signing key (DER).
- External sender package (opcode 25) when received.
- Send ratchet: one `KeyRatchet` for the local user (current epoch).
- Receive ratchets: dict `sender_user_id -> KeyRatchet` for other members.
- Key package bytes and group ID; epoch/transition and member leaf indices as needed.

---

## Methods

### prepare_epoch

```python
prepare_epoch(epoch_id: int) -> bytes | None
```

Prepares for a new epoch. Only when **epoch_id == 1** does it create a key package and return the **opcode 26** payload. For any other epoch ID it returns `None`.

- **When to call**: After select_protocol_ack or when the gateway signals “prepare epoch” with epoch 1.
- **Return value**: Bytes to send as opcode 26 (Key Package), or `None`.
- **Side effects**: Sets internal crypto provider, key package bytes, HPKE private key, and signing key when epoch_id is 1.

---

### handle_external_sender_package

```python
handle_external_sender_package(package_bytes: bytes) -> None
```

Processes **opcode 25** (External Sender Package). Parses and stores the external sender; if a key package was already prepared and no group exists yet, creates the initial MLS group and refreshes the send ratchet.

- **package_bytes**: Full opcode 25 payload (sequence + opcode + body).
- **Raises**: May raise on parse errors (e.g. `ValueError` from `parse_external_sender_package`).

---

### handle_proposals

```python
handle_proposals(proposal_bytes: bytes) -> bytes | None
```

Processes **opcode 27** (Proposals). Parses proposals, applies them to the group (if possible), and if operation type is “append” and the session can create a commit, returns the **opcode 28** payload (commit + optional welcome). Otherwise returns `None`.

- **proposal_bytes**: Full opcode 27 payload.
- **Return value**: Bytes to send as opcode 28, or `None` if no commit was created (e.g. no group, no signing key, or proposals not applicable).
- **Note**: Proposal application can fail for some members (e.g. external sender not in tree); the session skips failing proposals and still tries to create a commit when possible.

---

### handle_commit

```python
handle_commit(transition_id: int, commit_bytes: bytes) -> None
```

Processes **opcode 29** (Announce Commit). Applies the MLS commit to the group and refreshes receive ratchets.

- **transition_id**: Transition ID from the announce (e.g. from `parse_announce_commit`).
- **commit_bytes**: Serialized MLS commit (MLS Plaintext).
- **Raises**: **InvalidCommitError** if there is no group or commit application fails.

---

### handle_welcome

```python
handle_welcome(transition_id: int, welcome_bytes: bytes) -> None
```

Processes **opcode 30** (Welcome). Joins the group from the welcome (used when you were added). Refreshes receive and send ratchets.

- **transition_id**: Transition ID from the welcome message.
- **welcome_bytes**: Serialized MLS Welcome.
- **Raises**: **ValueError** if no HPKE private key is available (e.g. `prepare_epoch(1)` was never called or key was discarded).

---

### execute_transition

```python
execute_transition(transition_id: int) -> None
```

Processes **opcode 22** (Execute Transition). Rotates send and receive ratchets to the new epoch (keys are re-derived from the current MLS exporter state). Does not change group membership; only updates key material.

- **transition_id**: Transition ID from the opcode 22 payload (e.g. from `parse_execute_transition`).

---

### leave_group

```python
leave_group() -> bytes | None
```

Tears down local MLS group state: clears group, send/receive ratchets, member state, key package bytes, and epoch. If the session had a group and a signing key, it attempts to create a **Remove** proposal for the local member and returns its serialized bytes to send (e.g. via opcode 27); otherwise returns `None`.

- **Return value**: Serialized Remove proposal bytes, or `None`.

---

### get_encryptor

```python
get_encryptor() -> FrameEncryptor
```

Returns a **FrameEncryptor** for the local user’s outgoing frames, using the current send ratchet.

- **Returns**: `FrameEncryptor` instance.
- **Raises**: **RuntimeError** if no send ratchet exists (group not established). The session may try to refresh the send ratchet once before raising.

---

### get_decryptor

```python
get_decryptor(sender_id: int) -> FrameDecryptor
```

Returns a **FrameDecryptor** for the given remote sender.

- **sender_id** (int): Remote sender’s user ID.
- **Returns**: `FrameDecryptor` instance.
- **Raises**: **KeyError** if no receive ratchet exists for that sender (e.g. not in group or leaf unknown). The session may try to refresh receive ratchets once before raising.

---

## Usage summary

| Step | Method / Opcode |
|------|------------------|
| Create | `DaveSession(local_user_id=...)` |
| First key package | `prepare_epoch(1)` → send as opcode 26 |
| External sender | `handle_external_sender_package(opcode_25_payload)` |
| Proposals | `handle_proposals(opcode_27_payload)` → send return value as opcode 28 if not None |
| Commit | `parse_announce_commit` → `handle_commit(transition_id, commit_bytes)` |
| Welcome (you added) | `parse_welcome_message` → `handle_welcome(transition_id, welcome_bytes)` |
| Rotate keys | `parse_execute_transition` → `execute_transition(transition_id)` |
| Encrypt | `get_encryptor().encrypt(encoded_frame, codec="OPUS")` |
| Decrypt | `get_decryptor(sender_id).decrypt(protocol_frame)` |
| Leave | `leave_group()` → optionally send returned proposal as opcode 27 |

---

## API reference (auto-generated)

::: sorrydave.session.DaveSession
