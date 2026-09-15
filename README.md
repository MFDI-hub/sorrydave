# sorrydave

Should be production-quality Python library for the **DAVE** (Discord Audio/Video End-to-End Encryption) protocol. Currently it passes the tests i made but i have problem using it. I mean the library it uses(rfc9420) passes official vectors. It implements the protocol as a **pure data-transformation and state-management layer** on top of [rfc9420](https://pypi.org/project/rfc9420/) (PyMLS), with **no I/O or networking**: you pass in bytes (Voice Gateway opcodes, encoded media frames) and get back bytes (opcode payloads, encrypted/decrypted frames).

## Features

- **MLS integration**: Key packages, external sender handling, proposals, commit/welcome (opcodes 25–30), exporter-based sender keys
- **Sender key ratchet**: Per-sender, per-epoch keys via MLS-Exporter + HKDF; cache for out-of-order decryption
- **Frame transform**: Codec-aware encrypt/decrypt (OPUS, VP9, VP8, H264, H265, AV1), ULEB128, truncated AES128-GCM, DAVE footer (`0xFAFA`)
- **Identity**: Pairwise fingerprint (scrypt) and displayable codes (45-digit / 30-digit)
- **Voice Gateway helpers**: Parse-and-apply wrappers that return explicit `applied` / `media_ready` results without sending frames

## Install

```bash
pip install -e .
```

Requires Python 3.9+, `rfc9420`, `cryptography`, and `pycryptodome`.

## Minimal lifecycle

1. Create a session: `DaveSession(local_user_id=123456789, channel_id=voice_channel_id)`. The MLS group ID is the channel snowflake as 8 big-endian bytes; Discord will silently drop commits that use any other group ID. For Go Live, pass `channel_id=mls_channel_id_from_stream_server_id(rtc_server_id)`.
2. On **select_protocol_ack** (or **prepare_epoch** with `epoch=1`), call `session.prepare_epoch(1)` and send the returned bytes as opcode 26 (Key Package).
3. On **opcode 11 / 13**, call `sync_clients_connect` / `sync_client_disconnect` (or the session `add_expected_members` / `remove_expected_member` methods). If opcode 11 listed other users before this session existed, call `configure_occupied_join(...)` so you wait for opcode 30 instead of committing a local group.
4. On **opcode 25**, call `handle_external_sender_wire(session, package_bytes)`.
5. On **opcode 27**, call `apply_proposals_message(session, proposal_bytes)`. After a short quiet period, send `session.take_commit_welcome()` as opcode 28 if it returns bytes. Batching and the send itself stay in the caller.
6. On **opcode 29 / 30**, call `handle_announce_commit_wire` / `handle_welcome_wire`. If `applied` is True and media is ready, send opcode 23 with `build_ready_for_transition_dict(transition_id)`. Do not execute the transition here.
7. On **opcode 22**, parse with `parse_execute_transition` (or `handle_execute_transition_message`) and then switch send ratchets. Senders must keep the previous epoch until this opcode, per protocol.md.
8. Media: `session.encrypt_frame(frame, codec="OPUS")` and `session.decrypt_frame(protocol_frame, sender_id)`. Silence packets (`SILENCE_PACKET`) and frames that fail `protocol_frame_check` pass through.

**Error recovery:** On `InvalidCommitError`, call `recover_invalid_commit(session, transition_id)` and send the returned opcode 31 JSON, then the opcode 26 key package. Do not send opcode 23 or execute opcode 22 for the rejected transition.

**Caller-owned:** Voice Gateway WebSocket I/O, proposal coalescing timers, opcode 23 sends, opcode 22 execution policy (including the documented `transition_id=0` init path), recovery retry caps, and join watchdogs.

## API overview

- **`DaveSession`**: `handle_external_sender_package`, `prepare_epoch`, `apply_proposals`, `take_commit_welcome`, `handle_commit`, `handle_welcome`, `execute_transition`, `configure_occupied_join`, `leave_group`, `encrypt_frame`, `decrypt_frame`, `receive_ratchet_user_ids`
- **`sorrydave.voice_gateway`**: `sync_clients_connect`, `handle_external_sender_wire`, `apply_proposals_message`, `handle_announce_commit_wire`, `handle_welcome_wire`, `recover_invalid_commit`
- **`FrameEncryptor.encrypt(encoded_frame, codec)`** / **`FrameDecryptor.decrypt(protocol_frame)`**
- **`generate_fingerprint(local_id, local_pub, remote_id, remote_pub)`** → 45-digit string
- **`displayable_code(data, total_digits, group_size)`** for epoch authenticator (e.g. 30 digits, group 5)

## Scope

- **In scope**: MLS state, ratchet, OPUS/VP9/VP8/H264/H265/AV1 codec handling, frame encrypt/decrypt, identity fingerprint, opcode parse/build, and transport-free Voice Gateway helpers.
- **Out of scope**: Voice Gateway WebSocket I/O, proposal debounce timers, SFU silence-packet generation, WebRTC depacketizer patches.

## License

MIT.
