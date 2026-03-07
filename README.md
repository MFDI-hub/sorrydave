# pydave

Production-quality Python library for the **DAVE** (Discord Audio/Video End-to-End Encryption) protocol. It implements the protocol as a **pure data-transformation and state-management layer** on top of [rfc9420](https://pypi.org/project/rfc9420/) (PyMLS), with **no I/O or networking**: you pass in bytes (Voice Gateway opcodes, encoded media frames) and get back bytes (opcode payloads, encrypted/decrypted frames).

## Features

- **MLS integration**: Key packages, external sender handling, proposals, commit/welcome (opcodes 25–30), exporter-based sender keys
- **Sender key ratchet**: Per-sender, per-epoch keys via MLS-Exporter + HKDF; cache for out-of-order decryption
- **Frame transform**: Codec-aware encrypt/decrypt (OPUS, VP9, VP8 P-bit), ULEB128, truncated AES128-GCM, DAVE footer (`0xFAFA`)
- **Identity**: Pairwise fingerprint (scrypt) and displayable codes (45-digit / 30-digit)

## Install

```bash
pip install -e .
```

Requires Python 3.9+, `rfc9420`, `cryptography`, and `pycryptodome`.

## Minimal lifecycle

1. Create a session: `DaveSession(local_user_id=123456789)`.
2. On **select_protocol_ack** (or **prepare_epoch** with `epoch=1`), call `session.prepare_epoch(1)` and send the returned bytes as opcode 26 (Key Package).
3. On **opcode 25** (External Sender Package), call `session.handle_external_sender_package(package_bytes)`.
4. On **opcode 27** (Proposals), call `session.handle_proposals(proposal_bytes)`; if it returns bytes, send them as opcode 28.
5. On **opcode 29** (Announce Commit), call `session.handle_commit(transition_id, commit_bytes)`.
6. On **opcode 30** (Welcome), call `session.handle_welcome(transition_id, welcome_bytes)`.
7. On **opcode 22** (Execute Transition), call `session.execute_transition(transition_id)`.
8. Use `session.get_encryptor().encrypt(frame, codec="OPUS")` and `session.get_decryptor(sender_id).decrypt(protocol_frame)` for media.

## API overview

- **`DaveSession`**: `handle_external_sender_package`, `prepare_epoch`, `handle_proposals`, `handle_commit`, `handle_welcome`, `execute_transition`, `get_encryptor`, `get_decryptor`
- **`FrameEncryptor.encrypt(encoded_frame, codec)`** / **`FrameDecryptor.decrypt(protocol_frame)`**
- **`generate_fingerprint(local_id, local_pub, remote_id, remote_pub)`** → 45-digit string
- **`displayable_code(data, total_digits, group_size)`** for epoch authenticator (e.g. 30 digits, group 5)

## Scope

- **In scope**: MLS state, ratchet, OPUS/VP9/VP8 codec handling, frame encrypt/decrypt, identity fingerprint.
- **Out of scope**: Voice Gateway WebSocket I/O, SFU silence packets, WebRTC depacketizer patches. H264/H265 and AV1 are deferred.

## License

MIT.
