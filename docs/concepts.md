# Concepts

This page explains the main concepts used by sorrydave: epochs, transitions, the Voice Gateway opcode flow, codec handling, and identity.

---

## Epochs and transitions

- **Epoch**: A version of the MLS group state. When the group is updated (add/remove/update members), a new epoch is established. Media keys are derived per epoch (and per sender) from the MLS exporter.
- **Transition**: A logical step from one epoch to the next. The Voice Gateway coordinates this with **opcode 22 (Execute Transition)**. When you receive opcode 22, you call `session.execute_transition(transition_id)` so the session refreshes send/receive ratchets from the new epoch.
- **Epoch ID 1**: The first time you prepare an epoch (e.g. after select_protocol_ack or “prepare epoch”), use `epoch_id=1`. Only for `epoch_id == 1` does `prepare_epoch` return a key package to send as **opcode 26**.

---

## Voice Gateway opcode flow (summary)

| Opcode | Name | Direction | Purpose |
|--------|------|-----------|---------|
| 22 | Execute Transition | Inbound (JSON) | Tells client to rotate ratchets to the new epoch; parse with `parse_execute_transition`, then `session.execute_transition(transition_id)`. |
| 25 | External Sender Package | Inbound | MLS external sender credential/signature key; pass payload to `session.handle_external_sender_package(package_bytes)`. |
| 26 | Key Package | Outbound | Your key package; send the bytes returned from `session.prepare_epoch(1)`. |
| 27 | Proposals | Inbound | MLS proposals (add/remove/update); pass to `session.handle_proposals(proposal_bytes)`; may return opcode 28 payload. |
| 28 | Commit / Welcome | Outbound | Commit (and optional welcome); send the bytes returned from `session.handle_proposals(...)`. |
| 29 | Announce Commit | Inbound | Commit from another member; parse transition_id and commit bytes, then `session.handle_commit(transition_id, commit_bytes)`. |
| 30 | Welcome | Inbound | Welcome when you were added; parse transition_id and welcome bytes, then `session.handle_welcome(transition_id, welcome_bytes)`. |
| 31 | Invalid Commit/Welcome | Outbound (JSON) | After `InvalidCommitError`, send `build_invalid_commit_welcome(transition_id)` then send new key package (26). |

All opcode payloads are **bytes** (binary or UTF-8 JSON for 22/31). sorrydave does not open sockets; your application sends/receives these on the Voice Gateway.

---

## Session lifecycle (high level)

1. **Create session**: `DaveSession(local_user_id=...)`
2. **Prepare epoch 1**: `prepare_epoch(1)` → send returned bytes as opcode 26.
3. **Receive opcode 25**: `handle_external_sender_package(package_bytes)` (creates group when key package was already prepared).
4. **Receive opcode 27**: `handle_proposals(proposal_bytes)` → if return value is not None, send it as opcode 28.
5. **Receive opcode 29**: Parse payload for `transition_id` and commit bytes → `handle_commit(transition_id, commit_bytes)`.
6. **Receive opcode 30**: Parse payload for `transition_id` and welcome bytes → `handle_welcome(transition_id, welcome_bytes)` (when you were added).
7. **Receive opcode 22**: Parse JSON for `transition_id` → `execute_transition(transition_id)`.
8. **Media**: `get_encryptor()` / `get_decryptor(sender_id)` to encrypt outgoing and decrypt incoming frames.

On **InvalidCommitError**: send opcode 31 (`build_invalid_commit_welcome(transition_id)`), then `prepare_epoch(1)` and send the new key package as opcode 26.

---

## Codec-aware encryption

Media frames are not encrypted as one contiguous block. Some bytes are left **unencrypted** so the SFU can route or parse headers (e.g. codec type, key frame). sorrydave computes these ranges per codec:

| Codec | Unencrypted part |
|-------|-------------------|
| OPUS, VP9 | None (full frame encrypted). |
| VP8 | First 1 byte (delta) or 10 bytes (key frame), per P bit. |
| H264 | 1-byte NAL header for non-VCL NALs; VCL encrypted. |
| H265/HEVC | 2-byte NAL header for non-VCL NALs. |
| AV1 | OBU header, optional extension, optional size (LEB128); payload encrypted. OBU types 2, 8, 15 skipped. |

For H264/H265, 3-byte start codes (`0x000001`) in unencrypted sections are expanded to 4-byte (`0x00000001`) per protocol. The **supplemental footer** (at the end of each protocol frame) stores the 8-byte GCM tag, ULEB128 nonce, ULEB128 offset/length pairs for unencrypted ranges, size byte, and magic `0xFAFA`.

---

## Sender key ratchet

- Each **sender** (identified by user ID) has a **base secret** from the MLS exporter: `export_secret("Discord Secure Frames v0", context=sender_user_id_le, 16)`.
- From that, **KeyRatchet** derives a 128-bit AES key per **generation**. Generation is taken from the high byte of the 32-bit nonce in the frame footer.
- **Encryptor**: Uses a monotonic nonce; generation = nonce >> 24; key = ratchet.get_key_for_generation(generation).
- **Decryptor**: Reads footer, gets generation from nonce, looks up key (or derives and caches). Rejects **nonce reuse** and enforces **max forward gap** (DoS protection).
- When the epoch changes (commit/welcome/execute transition), the session refreshes ratchets from the new exporter state.

---

## Identity and verification

- **Pairwise fingerprint**: From local and remote user IDs and public keys, sorted and fed to scrypt; result is a **45-digit** displayable code (9 groups of 5). Use for “verify this user” UI.
- **Epoch authenticator**: A 32-byte exported secret from MLS can be shown as a **30-digit** code (6 groups of 5) via `epoch_authenticator_display`.
- **Displayable code**: Generic encoding of bytes as zero-padded numeric groups (e.g. 5 digits per group) for any length.

---

## Exceptions

- **DaveProtocolError**: Base for all DAVE-related errors.
- **DecryptionError**: GCM verification failed, nonce reuse, or invalid frame/supplemental. Fail closed: drop the frame.
- **InvalidCommitError**: Commit or welcome could not be applied. Respond with opcode 31 and a new key package (opcode 26).

See [Types & exceptions](api/types.md) for the full list and usage.
