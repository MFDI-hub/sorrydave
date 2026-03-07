# Quick start

Minimal lifecycle for a DAVE media session.

## 1. Create a session

```python
from pydave import DaveSession

session = DaveSession(local_user_id=123456789)
```

## 2. On select_protocol_ack or prepare_epoch (epoch=1)

Call `prepare_epoch(1)` and send the returned bytes as **opcode 26** (Key Package):

```python
key_package = session.prepare_epoch(1)
if key_package is not None:
    # Send key_package as opcode 26 payload to the voice gateway
    send_opcode_26(key_package)
```

## 3. On opcode 25 (External Sender Package)

```python
session.handle_external_sender_package(package_bytes)
```

## 4. On opcode 27 (Proposals)

```python
commit_payload = session.handle_proposals(proposal_bytes)
if commit_payload is not None:
    # Send commit_payload as opcode 28
    send_opcode_28(commit_payload)
```

## 5. On opcode 29 (Announce Commit)

```python
session.handle_commit(transition_id, commit_bytes)
```

## 6. On opcode 30 (Welcome)

```python
session.handle_welcome(transition_id, welcome_bytes)
```

## 7. On opcode 22 (Execute Transition)

Parse the payload to get `transition_id`, then execute the transition:

```python
from pydave.mls import parse_execute_transition

transition_id = parse_execute_transition(payload)[0]
session.execute_transition(transition_id)
```

## 8. Encrypt and decrypt media

```python
encryptor = session.get_encryptor()
decryptor = session.get_decryptor(sender_id)

# Outgoing: encode frame, then encrypt
encrypted = encryptor.encrypt(encoded_frame, codec="OPUS")

# Incoming: decrypt protocol frame
decrypted = decryptor.decrypt(protocol_frame)
```

## Error recovery

On `InvalidCommitError`:

1. Send `build_invalid_commit_welcome(transition_id)` as **opcode 31** to the voice gateway.
2. Call `session.prepare_epoch(1)` and send the returned key package as opcode 26.

```python
from pydave import InvalidCommitError
from pydave.mls import build_invalid_commit_welcome

try:
    session.handle_commit(transition_id, commit_bytes)
except InvalidCommitError:
    invalid_welcome = build_invalid_commit_welcome(transition_id)
    send_opcode_31(invalid_welcome)
    key_package = session.prepare_epoch(1)
    if key_package:
        send_opcode_26(key_package)
```
