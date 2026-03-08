# Troubleshooting

This page covers common errors, how to recover, and practical debug tips when integrating sorrydave with a Voice Gateway or media pipeline.

---

## Common errors and recovery

### InvalidCommitError

**When it happens:** `session.handle_commit(transition_id, commit_bytes)` raises `InvalidCommitError` when there is no group, the commit is invalid, or rfc9420 rejects the commit (e.g. signature or membership issue).

**Recovery (required by the protocol):**

1. Send **opcode 31** (Invalid Commit/Welcome) with the same `transition_id`:
   ```python
   from sorrydave.mls import build_invalid_commit_welcome
   payload_31 = build_invalid_commit_welcome(transition_id)
   send_opcode_31(payload_31)  # Your gateway send
   ```
2. Call `session.prepare_epoch(1)` and send the returned bytes as **opcode 26** (Key Package):
   ```python
   key_package = session.prepare_epoch(1)
   if key_package:
       send_opcode_26(key_package)
   ```

Do not retry `handle_commit` with the same commit bytes; the session state may be inconsistent until you complete the recovery above.

---

### DecryptionError

**When it happens:** `decryptor.decrypt(protocol_frame)` raises `DecryptionError` when GCM verification fails, the nonce was reused, the frame or supplemental footer is invalid, or the key does not match (e.g. wrong sender or epoch).

**Action:** Fail closed: drop the frame and do not use its content. Do not retry decryption with the same frame.

**Possible causes:**

- Wrong sender ID (key from another participant).
- Epoch mismatch (opcode 22 not yet processed, or processed in wrong order).
- Corrupted or truncated frame.
- Nonce reuse (replay or bug in sender).

---

### KeyError from get_decryptor(sender_id)

**When it happens:** `session.get_decryptor(sender_id)` raises `KeyError` when there is no receive ratchet for that sender. Typical causes: the sender is not in the current group, or their leaf index is not yet known (e.g. you have not applied a commit that adds them, or you have not called `execute_transition` after the commit).

**Action:**

- Ensure you have called `handle_commit(transition_id, commit_bytes)` for commits that add or update that sender, and then **opcode 22** with `execute_transition(transition_id)` so the session refreshes receive ratchets from the new epoch.
- If you were added via a welcome, ensure `handle_welcome(transition_id, welcome_bytes)` was called, then process opcode 22 when the gateway sends it.
- Do not call `get_decryptor(sender_id)` for users who are not in the group.

---

### RuntimeError from get_encryptor()

**When it happens:** `session.get_encryptor()` raises `RuntimeError` when there is no send ratchet (group not established or keys not yet derived).

**Action:**

- Ensure you have called `prepare_epoch(1)` and sent the key package as opcode 26.
- Then ensure you have called `handle_external_sender_package(opcode_25_payload)` so the session can create the group and refresh the send ratchet.
- If the gateway sends opcode 27 (proposals) and you send opcode 28 (commit/welcome), you may still need to receive and process opcode 22 (execute transition) before the encryptor is ready, depending on how the session refreshes ratchets. Call `get_encryptor()` only after the session has a current send ratchet (e.g. after execute_transition for the current epoch).

---

### ValueError from handle_welcome or key operations

**When it happens:** `handle_welcome(transition_id, welcome_bytes)` can raise `ValueError` if no HPKE private key is available (e.g. `prepare_epoch(1)` was never called or the key was discarded). Other parsing or key errors may also surface as `ValueError`.

**Action:** Ensure the session has prepared epoch 1 and stored the key package (and HPKE private key) before handling a welcome that adds the local user. Check [Installation](installation.md) and [Quick start](quickstart.md) for the correct order of operations.

---

## Import and dependency issues

- **ImportError for rfc9420, cryptography, or Crypto:** Install sorrydave and its dependencies from the project root: `pip install -e .` (or use a virtual environment). See [Installation](installation.md).
- **Python version:** Use Python 3.9 or newer. Run `python --version` or `python3 --version` and, if needed, use the correct interpreter for `pip install -e .`.

---

## Debug tips

- **Log transition_id and epoch:** When handling opcodes 29, 30, and 22, log `transition_id` so you can verify that execute_transition is called with the same ID that was announced. This helps catch ordering or duplicate-message issues.
- **Verify opcode order:** Ensure you do not process opcode 27 before opcode 25 (external sender), and that you process 29/30 before 22 when the gateway sends them in that order. The session expects the group and commit/welcome state to be applied before ratchets are rotated via opcode 22.
- **Frame format:** If decryption fails often, confirm that incoming frames are full protocol frames (with the DAVE supplemental footer including magic `0xFAFA`). Use `protocol_frame_check(frame)` from `sorrydave.media.transform` to quickly check whether the frame has the expected footer structure.
