# PyDAVE

Production-quality Python library for the **DAVE** (Discord Audio/Video End-to-End Encryption) protocol. It implements the protocol as a **pure data-transformation and state-management layer** on top of [rfc9420](https://pypi.org/project/rfc9420/) (PyMLS), with **no I/O or networking**: you pass in bytes (Voice Gateway opcodes, encoded media frames) and get back bytes (opcode payloads, encrypted/decrypted frames).

## Features

- **MLS integration**: Key packages, external sender handling, proposals, commit/welcome (opcodes 25–30), exporter-based sender keys
- **Sender key ratchet**: Per-sender, per-epoch keys via MLS-Exporter + HKDF; cache for out-of-order decryption
- **Frame transform**: Codec-aware encrypt/decrypt (OPUS, VP9, VP8, H264, H265, AV1), ULEB128, truncated AES128-GCM, DAVE footer (`0xFAFA`)
- **Identity**: Pairwise fingerprint (scrypt) and displayable codes (45-digit / 30-digit)

## Scope

- **In scope**: MLS state, ratchet, OPUS/VP9/VP8/H264/H265/AV1 codec handling, frame encrypt/decrypt, identity fingerprint, opcode 22 parse and opcode 31 build for transition and error recovery.
- **Out of scope**: Voice Gateway WebSocket I/O, SFU silence packets, WebRTC depacketizer patches.

## Links

- [Installation](installation.md)
- [Quick start](quickstart.md)
- [API reference](api/session.md)
