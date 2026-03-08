# Quick start

This page walks through a minimal DAVE media session lifecycle: create a session, prepare the first epoch, handle Voice Gateway opcodes 25–30 and 22, encrypt/decrypt media, and recover from an invalid commit.

---

## Prerequisites

- **Python 3.9+** with sorrydave installed (see [Installation](installation.md)).
- Your application is responsible for **Voice Gateway I/O**: sending and receiving opcode payloads (e.g. over WebSocket) and media frames. sorrydave only consumes and produces bytes; it does not open sockets or perform network I/O.

---

## 1. Create a session

Create a `DaveSession` with your local user ID (e.g. Discord snowflake). The session holds MLS group state and per-sender ratchets; it does not perform any I/O.

```python
from sorrydave import DaveSession

session = DaveSession(local_user_id=123456789)
# Optional: session = DaveSession(local_user_id=123456789, protocol_version=1)
```

---

## 2. Prepare epoch 1 (e.g. after select_protocol_ack or prepare_epoch)

When the Voice Gateway signals that the protocol is selected or that you should prepare an epoch, call `prepare_epoch(1)`. Only for **epoch_id == 1** does this return bytes; those bytes are the **opcode 26 (Key Package)** payload to send to the voice gateway.

```python
key_package = session.prepare_epoch(1)
if key_package is not None:
    # Send key_package as opcode 26 payload to the voice gateway
    send_opcode_26(key_package)
```

If you call `prepare_epoch(2)` or any other epoch ID, it returns `None` (no key package is built).

---

## 3. Handle opcode 25 (External Sender Package)

When you receive an **opcode 25** payload from the gateway, pass the raw bytes to the session. This stores the external sender and, if a key package was already prepared and crypto is ready, creates the initial MLS group and refreshes the send ratchet.

```python
session.handle_external_sender_package(package_bytes)
```

---

## 4. Handle opcode 27 (Proposals)

When you receive **opcode 27** (proposals), pass the payload to the session. If the session can create a commit (and optionally a welcome), it returns the **opcode 28** payload to send. Otherwise it returns `None`.

```python
commit_payload = session.handle_proposals(proposal_bytes)
if commit_payload is not None:
    # Send commit_payload as opcode 28
    send_opcode_28(commit_payload)
```

---

## 5. Handle opcode 29 (Announce Commit)

When you receive **opcode 29**, parse the payload to get `transition_id` and the commit message bytes, then apply the commit. This updates the group and refreshes receive ratchets.

```python
from sorrydave.mls.opcodes import parse_announce_commit

transition_id, commit_bytes = parse_announce_commit(payload)
session.handle_commit(transition_id, commit_bytes)
```

If the commit cannot be applied, the session raises **InvalidCommitError**; see [Error recovery](#error-recovery) below.

---

## 6. Handle opcode 30 (Welcome)

When you receive **opcode 30** (e.g. you were added to the group), parse the payload and pass the welcome to the session. The session joins the group from the welcome and refreshes send/receive ratchets.

```python
from sorrydave.mls.opcodes import parse_welcome_message

transition_id, welcome_bytes = parse_welcome_message(payload)
session.handle_welcome(transition_id, welcome_bytes)
```

This requires the HPKE private key from the key package that was added; the session stores it when you call `prepare_epoch(1)`.

---

## 7. Handle opcode 22 (Execute Transition)

When you receive **opcode 22** (Execute Transition), the payload is JSON. Parse it to get `transition_id`, then tell the session to rotate ratchets to the new epoch.

```python
from sorrydave.mls import parse_execute_transition

# payload is the raw bytes of the opcode 22 message (e.g. UTF-8 JSON)
transition_id = parse_execute_transition(payload)
session.execute_transition(transition_id)
```

After this, `get_encryptor()` and `get_decryptor(sender_id)` use keys from the new epoch.

---

## 8. Encrypt and decrypt media

Get an encryptor for your own outgoing frames and a decryptor per remote sender. Encrypt **encoded** frames (after your codec encoder); decrypt **protocol** frames (bytes that include the DAVE footer).

```python
# Outgoing: encode frame with your codec, then encrypt
encryptor = session.get_encryptor()
encrypted = encryptor.encrypt(encoded_frame, codec="OPUS")
# Send `encrypted` over the media channel

# Incoming: decrypt protocol frame, then pass plaintext to your codec decoder
decryptor = session.get_decryptor(sender_id)
decrypted = decryptor.decrypt(protocol_frame)
# Decode `decrypted` with the appropriate codec
```

Supported `codec` values include: `"OPUS"`, `"VP9"`, `"VP8"`, `"H264"` / `"H.264"`, `"H265"` / `"H265/HEVC"` / `"HEVC"`, `"AV1"`. Case-insensitive. Unknown codecs are treated as full-frame encryption.

---

## Error recovery

### InvalidCommitError

If `handle_commit(transition_id, commit_bytes)` raises **InvalidCommitError**, the protocol requires you to:

1. Send **opcode 31** (Invalid Commit/Welcome) with the same `transition_id`.
2. Call `prepare_epoch(1)` and send the returned key package as **opcode 26**.

Example:

```python
from sorrydave import InvalidCommitError
from sorrydave.mls import build_invalid_commit_welcome

try:
    session.handle_commit(transition_id, commit_bytes)
except InvalidCommitError:
    invalid_welcome = build_invalid_commit_welcome(transition_id)
    send_opcode_31(invalid_welcome)
    key_package = session.prepare_epoch(1)
    if key_package:
        send_opcode_26(key_package)
```

### DecryptionError

If `decryptor.decrypt(protocol_frame)` raises **DecryptionError** (e.g. GCM failure, nonce reuse), drop the frame and do not use its content. Do not retry with the same frame.

### No ratchet for sender

If `get_decryptor(sender_id)` raises **KeyError**, there is no receive ratchet for that sender (e.g. they are not in the current group or their leaf is not yet known). Refresh or wait for group updates.

---

## Leaving the group

To tear down local MLS state and optionally send a Remove proposal for yourself:

```python
remove_proposal_bytes = session.leave_group()
if remove_proposal_bytes is not None:
    # Send remove_proposal_bytes as part of opcode 27 (proposals)
    send_proposals_append(remove_proposal_bytes)
```

After `leave_group()`, the session has no group; you must go through prepare_epoch(1) and the opcode flow again to rejoin.

---

## Full example (end-to-end script)

The script below wires a minimal session to stub I/O. Replace `send_opcode_*` and the "receive" placeholders with your real Voice Gateway and media pipeline.

```python
from sorrydave import DaveSession
from sorrydave.mls import (
    parse_announce_commit,
    parse_execute_transition,
    parse_external_sender_package,
    parse_welcome_message,
)

def send_opcode_26(payload: bytes) -> None:
    """Send key package to voice gateway."""
    pass  # Your implementation

def send_opcode_28(payload: bytes) -> None:
    """Send commit/welcome to voice gateway."""
    pass  # Your implementation

# 1. Create session
session = DaveSession(local_user_id=123456789)

# 2. Prepare epoch 1 and send key package
key_package = session.prepare_epoch(1)
if key_package:
    send_opcode_26(key_package)

# 3. When you receive opcode 25 (external sender package)
# package_25_bytes = ...  # from gateway
# session.handle_external_sender_package(package_25_bytes)

# 4. When you receive opcode 27 (proposals)
# proposal_bytes = ...  # from gateway
# commit_payload = session.handle_proposals(proposal_bytes)
# if commit_payload:
#     send_opcode_28(commit_payload)

# 5. When you receive opcode 29 (announce commit)
# payload_29 = ...  # from gateway
# transition_id, commit_bytes = parse_announce_commit(payload_29)
# session.handle_commit(transition_id, commit_bytes)

# 6. When you receive opcode 30 (welcome, if you were added)
# payload_30 = ...  # from gateway
# transition_id, welcome_bytes = parse_welcome_message(payload_30)
# session.handle_welcome(transition_id, welcome_bytes)

# 7. When you receive opcode 22 (execute transition)
# payload_22 = ...  # from gateway
# transition_id = parse_execute_transition(payload_22)
# session.execute_transition(transition_id)

# 8. Encrypt one outgoing frame and decrypt one incoming (after group is ready)
# encryptor = session.get_encryptor()
# encrypted = encryptor.encrypt(encoded_frame, codec="OPUS")
# decryptor = session.get_decryptor(remote_sender_id)
# decrypted = decryptor.decrypt(protocol_frame)
```

---

## Next steps

- [Concepts](concepts.md) — Epochs, transitions, opcode flow, codecs, identity, frame layout.
- [Architecture](architecture.md) — Component diagram and data flow.
- [API → Session](api/session.md) — All `DaveSession` methods and parameters.
- [API → MLS & opcodes](api/mls.md) — Parse/build for opcodes 22, 25–31 and other Voice Gateway opcodes.
- [Troubleshooting](troubleshooting.md) — Common errors and recovery.
