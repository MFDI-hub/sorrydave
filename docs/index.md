# sorrydave

**sorrydave** is a production-quality Python library for the **DAVE** (Discord Audio/Video End-to-End Encryption) protocol. It implements the protocol as a **pure data-transformation and state-management layer** on top of [rfc9420](https://pypi.org/project/rfc9420/) (PyMLS), with **no I/O or networking**: you pass in bytes (Voice Gateway opcodes, encoded media frames) and get back bytes (opcode payloads, encrypted/decrypted frames).

---

## What DAVE does

DAVE provides **end-to-end encryption** for Discord voice/video: only participants in a call have the keys. The library handles:

- **MLS (Messaging Layer Security)** group setup and updates: key packages, external senders, proposals, commits, welcomes.
- **Per-sender key ratchets** derived from MLS exporter secrets, so each participant encrypts media with keys only receivers can derive.
- **Frame-level encryption** that is **codec-aware**: some bytes (e.g. codec headers for SFU routing) stay plaintext; the rest is encrypted with AES128-GCM and a DAVE protocol footer (tag, nonce, unencrypted ranges, magic `0xFAFA`).
- **Identity verification**: pairwise fingerprints (scrypt) and displayable numeric codes (45-digit fingerprint, 30-digit epoch authenticator).

---

## Features

| Feature | Description |
|--------|-------------|
| **MLS integration** | Key packages, external sender handling, proposals, commit/welcome (opcodes 25–30), exporter-based sender keys. |
| **Sender key ratchet** | Per-sender, per-epoch keys via MLS Exporter + HKDF; cache for out-of-order decryption; configurable retention and max forward gap. |
| **Frame transform** | Codec-aware encrypt/decrypt (OPUS, VP9, VP8, H264, H265, AV1), ULEB128, truncated AES128-GCM, DAVE footer (`0xFAFA`). |
| **Identity** | Pairwise fingerprint (scrypt) and displayable codes (45-digit / 30-digit). |
| **Opcodes** | Parse and build Voice Gateway opcodes: 22 (Execute Transition), 25–31 (MLS and invalid commit/welcome). |

---

## Scope

- **In scope**: MLS state, ratchet, OPUS/VP9/VP8/H264/H265/AV1 codec handling, frame encrypt/decrypt, identity fingerprint, opcode 22 parse and opcode 31 build for transition and error recovery.
- **Out of scope**: Voice Gateway WebSocket I/O, SFU silence packets, WebRTC depacketizer patches. Your application is responsible for sending/receiving opcode payloads over the gateway.

---

## Architecture (high level)

```
┌─────────────────────────────────────────────────────────────────┐
│  Your application (Voice Gateway, media pipeline)               │
│  - Receives opcode payloads (25–31, 22) and media frames         │
│  - Sends opcode payloads (26, 28, 31) and encrypted frames       │
└───────────────────────────────┬─────────────────────────────────┘
                                │ bytes in / bytes out
┌───────────────────────────────▼─────────────────────────────────┐
│  sorrydave                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │ DaveSession │  │ MLS opcodes  │  │ FrameEncryptor /         │ │
│  │ (facade)    │  │ parse/build │  │ FrameDecryptor           │ │
│  └──────┬──────┘  └──────┬───────┘  └───────────┬───────────────┘ │
│         │                │                      │                │
│  ┌──────▼──────┐  ┌──────▼───────┐  ┌───────────▼───────────────┐ │
│  │ group_state │  │ KeyRatchet   │  │ codecs + cipher           │ │
│  │ (rfc9420)   │  │ (HKDF cache)│  │ (AES128-GCM, ULEB128)     │ │
│  └─────────────┘  └─────────────┘  └───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

- **DaveSession**: Single entry point for “prepare epoch”, “handle opcode 25/27/29/30”, “execute transition”, “get encryptor/decryptor”.
- **MLS & opcodes**: Binary/JSON opcode parsing and building; group creation, key package, commit, welcome, remove/update proposals.
- **Media**: Codec-specific unencrypted ranges, interleaved encrypt/decrypt, DAVE supplemental footer.

---

## Documentation map

| Page | Contents |
|------|----------|
| [Installation](installation.md) | Python version, dependencies, pip/uv, optional docs build. |
| [Quick start](quickstart.md) | Minimal session lifecycle: create session, prepare epoch, handle opcodes 25–30, execute transition, encrypt/decrypt, error recovery. |
| [Concepts](concepts.md) | Epochs, transitions, opcode flow, codec handling, identity. |
| [API → Session](api/session.md) | `DaveSession`: all methods, parameters, return values, errors. |
| [API → Media](api/media.md) | `FrameEncryptor`, `FrameDecryptor`, codecs, supplemental data. |
| [API → Identity](api/identity.md) | `generate_fingerprint`, `displayable_code`, epoch authenticator. |
| [API → MLS & opcodes](api/mls.md) | Opcodes 22, 25–31; parse/build; group_state helpers. |
| [API → Types & exceptions](api/types.md) | `DaveConfiguration`, `IdentityConfig`, `UnencryptedRange`, `ProtocolSupplementalData`, exceptions. |

---

## Links

- [Installation](installation.md)
- [Quick start](quickstart.md)
- [Concepts](concepts.md)
- [API reference](api/session.md)
