"""
DAVE Voice Gateway opcode parsing and building (opcodes 0, 4, 11, 13, 21-24, 25-31).

Binary opcodes 25-30; JSON opcodes 0, 4, 11, 13, 21, 22, 23, 24, 31. No I/O; consumes/produces bytes only.

Public parse/build functions:
    - build_identify: Build opcode 0 (Identify) JSON; client sends to server.
    - parse_select_protocol_ack: Parse opcode 4 (Select Protocol Ack); returns protocol version.
    - parse_clients_connect: Parse opcode 11 (Clients Connect); returns list of user_ids.
    - parse_client_disconnect: Parse opcode 13 (Client Disconnect); returns user_id.
    - parse_prepare_transition: Parse opcode 21 (Prepare Transition); returns (protocol_version, transition_id).
    - parse_execute_transition: Parse opcode 22 (Execute Transition); returns transition_id.
    - build_ready_for_transition: Build opcode 23 (Ready For Transition) JSON.
    - parse_prepare_epoch: Parse opcode 24 (Prepare Epoch); returns (protocol_version, epoch).
    - parse_external_sender_package: Parse opcode 25 (External Sender Package).
    - build_key_package_message: Build opcode 26 (Key Package) payload.
    - parse_proposals: Parse opcode 27 (Proposals).
    - build_commit_welcome: Build opcode 28 (Commit/Welcome) payload.
    - parse_announce_commit: Parse opcode 29 (Announce Commit); returns (transition_id, commit_bytes).
    - parse_welcome_message: Parse opcode 30 (Welcome); returns (transition_id, welcome_bytes).
    - build_invalid_commit_welcome: Build opcode 31 (Invalid Commit/Welcome) JSON.
"""

import json
import struct
from dataclasses import dataclass
from typing import Any, Union

# Opcode values per protocol.md
OPCODE_IDENTIFY = 0
OPCODE_SELECT_PROTOCOL_ACK = 4
OPCODE_CLIENTS_CONNECT = 11
OPCODE_CLIENT_DISCONNECT = 13
OPCODE_PREPARE_TRANSITION = 21
OPCODE_EXECUTE_TRANSITION = 22
OPCODE_READY_FOR_TRANSITION = 23
OPCODE_PREPARE_EPOCH = 24
OPCODE_EXTERNAL_SENDER_PACKAGE = 25
OPCODE_KEY_PACKAGE = 26
OPCODE_PROPOSALS = 27
OPCODE_COMMIT_WELCOME = 28
OPCODE_ANNOUNCE_COMMIT = 29
OPCODE_WELCOME = 30
OPCODE_INVALID_COMMIT_WELCOME = 31

# MLS variable-length encoding: length prefix per RFC 9420 §2.1.2 (varint)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """
    Read MLS-style varint (variable-size length) from data at offset.

    Args:
        data (bytes): Buffer containing varint.
        offset (int): Start index.

    Returns:
        tuple[int, int]: (value, new_offset).

    Raises:
        ValueError: On varint overflow or truncated data.
    """
    if offset >= len(data):
        raise ValueError("Varint truncated")
    first = data[offset]
    prefix = first >> 6
    if prefix == 0b00:
        return first & 0x3F, offset + 1
    if prefix == 0b01:
        if offset + 2 > len(data):
            raise ValueError("Varint truncated")
        value = ((first & 0x3F) << 8) | data[offset + 1]
        return value, offset + 2
    if prefix == 0b10:
        if offset + 4 > len(data):
            raise ValueError("Varint truncated")
        value = (
            ((first & 0x3F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3]
        )
        return value, offset + 4
    raise ValueError("Varint overflow")


def _read_opaque_varint(data: bytes, offset: int) -> tuple[bytes, int]:
    """
    Read opaque<V>: varint length then that many bytes.

    Args:
        data (bytes): Buffer.
        offset (int): Start index.

    Returns:
        tuple[bytes, int]: (opaque bytes, new_offset).

    Raises:
        ValueError: If data is truncated.
    """
    length, pos = _read_varint(data, offset)
    if pos + length > len(data):
        raise ValueError("Opaque truncated")
    return data[pos : pos + length], pos + length


def _read_vector_varint(data: bytes, offset: int) -> tuple[bytes, int]:
    """
    Read vector<V>: varint length then that many bytes.

    Args:
        data (bytes): Buffer.
        offset (int): Start index.

    Returns:
        tuple[bytes, int]: (vector content bytes, new_offset).

    Raises:
        ValueError: If data is truncated.
    """
    length, pos = _read_varint(data, offset)
    if pos + length > len(data):
        raise ValueError("Vector truncated")
    return data[pos : pos + length], pos + length


@dataclass
class ExternalSenderPackage:
    """
    Parsed opcode 25: external sender credential and signature key.

    Attributes:
        sequence_number (int): Message sequence number.
        signature_key (bytes): Signature public key.
        credential_type (int): Credential type (e.g. BASIC).
        identity (bytes): Identity bytes (e.g. user ID).
    """

    sequence_number: int
    signature_key: bytes
    credential_type: int
    identity: bytes


def parse_external_sender_package(data: bytes) -> ExternalSenderPackage:
    """
    Parse DAVE_MLSExternalSenderPackage (opcode 25).

    Args:
        data (bytes): Full opcode 25 payload (sequence + opcode + body).

    Returns:
        ExternalSenderPackage: Parsed package.

    Raises:
        ValueError: If data too short or wrong opcode.
    """
    if len(data) < 2 + 1:
        raise ValueError("External sender package too short")
    (seq,) = struct.unpack("!H", data[:2])
    opcode = data[2]
    if opcode != OPCODE_EXTERNAL_SENDER_PACKAGE:
        raise ValueError(f"Expected opcode 25, got {opcode}")
    rest = data[3:]
    # SignaturePublicKey<V>
    sig_key, off = _read_opaque_varint(rest, 0)
    rest = rest[off:]
    # Credential: type (uint16) + identity<V>
    if len(rest) < 2:
        raise ValueError("Credential truncated")
    (cred_type,) = struct.unpack("!H", rest[:2])
    identity, _ = _read_opaque_varint(rest, 2)
    return ExternalSenderPackage(
        sequence_number=seq,
        signature_key=sig_key,
        credential_type=cred_type,
        identity=identity,
    )


def build_key_package_message(key_package_bytes: bytes) -> bytes:
    """
    Build opcode 26 payload: opcode (1) || MLSMessage (key package).

    Args:
        key_package_bytes (bytes): Serialized KeyPackage.

    Returns:
        bytes: Opcode 26 message bytes.
    """
    return bytes([OPCODE_KEY_PACKAGE]) + key_package_bytes


@dataclass
class ProposalsMessage:
    """
    Parsed opcode 27: append (proposal messages) or revoke (proposal refs).

    Attributes:
        sequence_number (int): Message sequence number.
        operation_type (int): 0 = append, 1 = revoke.
        proposal_messages (Union[list[bytes], None]): Serialized proposals (append only).
        proposal_refs (Union[list[bytes], None]): Proposal refs (revoke only).
    """

    sequence_number: int
    operation_type: int  # 0 = append, 1 = revoke
    proposal_messages: Union[list[bytes], None] = None
    proposal_refs: Union[list[bytes], None] = None


def parse_proposals(data: bytes) -> ProposalsMessage:
    """
    Parse DAVE_MLSProposals (opcode 27).

    Args:
        data (bytes): Full opcode 27 payload.

    Returns:
        ProposalsMessage: Parsed message.

    Raises:
        ValueError: If data too short, wrong opcode, or unknown operation type.
    """
    if len(data) < 2 + 1 + 1:
        raise ValueError("Proposals message too short")
    (seq,) = struct.unpack("!H", data[:2])
    opcode = data[2]
    if opcode != OPCODE_PROPOSALS:
        raise ValueError(f"Expected opcode 27, got {opcode}")
    op_type = data[3]
    if op_type not in (0, 1):
        raise ValueError(f"Unknown proposals operation type {op_type}")
    rest = data[4:]
    vector_bytes, end = _read_vector_varint(rest, 0)
    if end != len(rest):
        raise ValueError("Proposals trailing bytes")
    if op_type == 0:  # append
        # MLSMessage<V> is an MLS vector, where each element is a full MLSMessage.
        # We keep the vector payload as one message blob for downstream MLS parsing.
        return ProposalsMessage(
            sequence_number=seq,
            operation_type=0,
            proposal_messages=[vector_bytes],
        )
    else:  # revoke (op_type == 1, validated above)
        refs = []
        off = 0
        while off < len(vector_bytes):
            ref, off = _read_opaque_varint(vector_bytes, off)
            refs.append(ref)
        return ProposalsMessage(sequence_number=seq, operation_type=1, proposal_refs=refs)


def split_proposal_messages_vector(vector_payload: bytes) -> list[bytes]:
    """
    Split MLS proposal_messages vector payload into individual MLSMessage bytes.

    Each element is opaque<V> (varint length + bytes).

    Args:
        vector_payload (bytes): Raw vector content (no outer length prefix).

    Returns:
        list[bytes]: List of MLSMessage byte strings.
    """
    messages = []
    off = 0
    while off < len(vector_payload):
        try:
            msg_bytes, off = _read_opaque_varint(vector_payload, off)
            messages.append(msg_bytes)
        except ValueError:
            break
    return messages


def parse_announce_commit(data: bytes) -> tuple[int, bytes]:
    """
    Parse opcode 29: transition_id (uint16) + MLSMessage commit.

    Args:
        data (bytes): Full opcode 29 payload.

    Returns:
        tuple[int, bytes]: (transition_id, commit_message bytes).

    Raises:
        ValueError: If data too short or wrong opcode.
    """
    if len(data) < 2 + 1 + 2:
        raise ValueError("Announce commit too short")
    (seq,) = struct.unpack("!H", data[:2])
    opcode = data[2]
    if opcode != OPCODE_ANNOUNCE_COMMIT:
        raise ValueError(f"Expected opcode 29, got {opcode}")
    (transition_id,) = struct.unpack("!H", data[3:5])
    commit_message = data[5:]
    return transition_id, commit_message


def parse_welcome_message(data: bytes) -> tuple[int, bytes]:
    """
    Parse opcode 30: transition_id (uint16) + Welcome.

    Args:
        data (bytes): Full opcode 30 payload.

    Returns:
        tuple[int, bytes]: (transition_id, welcome bytes).

    Raises:
        ValueError: If data too short or wrong opcode.
    """
    if len(data) < 2 + 1 + 2:
        raise ValueError("Welcome message too short")
    (seq,) = struct.unpack("!H", data[:2])
    opcode = data[2]
    if opcode != OPCODE_WELCOME:
        raise ValueError(f"Expected opcode 30, got {opcode}")
    (transition_id,) = struct.unpack("!H", data[3:5])
    welcome_bytes = data[5:]
    return transition_id, welcome_bytes


def build_commit_welcome(commit_message: bytes, welcome_message: Union[bytes, None]) -> bytes:
    """
    Build opcode 28 payload: opcode || opaque<V>(commit) || optional welcome.

    Args:
        commit_message (bytes): Serialized MLS commit message.
        welcome_message (Union[bytes, None]): Optional serialized Welcome (not wrapped in MLSMessage).

    Returns:
        bytes: Opcode 28 message bytes.
    """
    out = bytes([OPCODE_COMMIT_WELCOME])
    # Real gateway captures encode the commit as an opaque<V>-style field.
    out += _write_opaque_varint(commit_message)
    if welcome_message:
        out += welcome_message  # Welcome is not wrapped in MLSMessage per DAVE struct
    return out


def parse_commit_welcome(data: bytes) -> tuple[bytes, Union[bytes, None]]:
    """
    Parse opcode 28: commit message + optional welcome.

    Args:
        data (bytes): Full opcode 28 payload.

    Returns:
        tuple[bytes, Union[bytes, None]]: (commit_message, welcome_message_or_none).

    Raises:
        ValueError: If data too short, wrong opcode, or commit is truncated.
    """
    if len(data) < 1:
        raise ValueError("Commit/welcome message too short")
    opcode = data[0]
    if opcode != OPCODE_COMMIT_WELCOME:
        raise ValueError(f"Expected opcode 28, got {opcode}")
    commit_message, off = _read_opaque_varint(data, 1)
    welcome_message = data[off:] if off < len(data) else None
    return commit_message, welcome_message


def _write_opaque_varint(data: bytes) -> bytes:
    """
    Write varint length prefix then data (opaque<V> encoding).

    Args:
        data (bytes): Payload to prefix.

    Returns:
        bytes: varint(len(data)) || data.
    """
    n = len(data)
    if n <= 0x3F:
        prefix = bytes([n])
    elif n <= 0x3FFF:
        prefix = bytes([0x40 | (n >> 8), n & 0xFF])
    elif n <= 0x3FFFFFFF:
        prefix = bytes(
            [
                0x80 | ((n >> 24) & 0x3F),
                (n >> 16) & 0xFF,
                (n >> 8) & 0xFF,
                n & 0xFF,
            ]
        )
    else:
        raise ValueError("Opaque too large")
    return prefix + data


# --- JSON opcodes (0, 4, 11, 13, 21, 22, 23, 24, 31) ---


def _parse_json_op(payload: bytes) -> dict[str, Any]:
    """Decode UTF-8 JSON and return the root object. Raises ValueError on failure."""
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError("Invalid JSON payload") from e
    if not isinstance(obj, dict):
        raise ValueError("Payload must be a JSON object")
    return obj


def build_identify(max_dave_protocol_version: int = 1, **d_extra: object) -> bytes:
    """
    Build opcode 0 (Identify) JSON payload. Client sends to server.

    Args:
        max_dave_protocol_version (int): Maximum supported DAVE protocol version. Default 1.
        **d_extra: Additional keys for the "d" object (e.g. server_id, user_id, session_id).

    Returns:
        bytes: UTF-8 JSON payload, e.g. {"op":0,"d":{"max_dave_protocol_version":1,...}}.

    When to call: At Voice Gateway connection start, before select_protocol_ack or prepare_epoch.
    """
    d = {"max_dave_protocol_version": max_dave_protocol_version, **d_extra}
    obj = {"op": OPCODE_IDENTIFY, "d": d}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def parse_select_protocol_ack(payload: bytes) -> int:
    """
    Parse opcode 4 (Select Protocol Ack) JSON payload. Server sends to client.

    Args:
        payload (bytes): UTF-8 JSON payload with "d.dave_protocol_version".

    Returns:
        int: dave_protocol_version (initial DAVE protocol version for the session).

    Raises:
        ValueError: If JSON invalid, missing "d", or missing/invalid dave_protocol_version.
    """
    obj = _parse_json_op(payload)
    d = obj.get("d")
    if not isinstance(d, dict):
        raise ValueError("select_protocol_ack must have 'd' object")
    v = d.get("dave_protocol_version")
    if v is None:
        raise ValueError("dave_protocol_version required")
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError("dave_protocol_version must be an integer") from None
    return v


def parse_clients_connect(payload: bytes) -> list[str]:
    """
    Parse opcode 11 (Clients Connect) JSON payload. Server sends to client.

    Args:
        payload (bytes): UTF-8 JSON payload with "d.user_ids" (list of strings).

    Returns:
        list[str]: user_ids (Discord snowflake user IDs as strings).

    Raises:
        ValueError: If JSON invalid or user_ids missing/not a list of strings.
    """
    obj = _parse_json_op(payload)
    d = obj.get("d")
    if not isinstance(d, dict):
        raise ValueError("clients_connect must have 'd' object")
    user_ids = d.get("user_ids")
    if not isinstance(user_ids, list):
        raise ValueError("user_ids must be a list")
    if not all(isinstance(u, str) for u in user_ids):
        raise ValueError("user_ids must be strings")
    return user_ids


def parse_client_disconnect(payload: bytes) -> str:
    """
    Parse opcode 13 (Client Disconnect) JSON payload. Server sends to client.

    Args:
        payload (bytes): UTF-8 JSON payload with "d.user_id" (string).

    Returns:
        str: user_id (Discord snowflake user ID that disconnected).

    Raises:
        ValueError: If JSON invalid or user_id missing/not a string.
    """
    obj = _parse_json_op(payload)
    d = obj.get("d")
    if not isinstance(d, dict):
        raise ValueError("client_disconnect must have 'd' object")
    user_id = d.get("user_id")
    if not isinstance(user_id, str):
        raise ValueError("user_id must be a string")
    return user_id


def parse_prepare_transition(payload: bytes) -> tuple[int, int]:
    """
    Parse opcode 21 (Prepare Transition) JSON payload. Server sends to client.

    Args:
        payload (bytes): UTF-8 JSON with "d.protocol_version" and "d.transition_id".

    Returns:
        tuple[int, int]: (protocol_version, transition_id). transition_id 0 = execute immediately.

    Raises:
        ValueError: If JSON invalid, fields missing, or transition_id not in uint16 range.
    """
    obj = _parse_json_op(payload)
    d = obj.get("d")
    if not isinstance(d, dict):
        raise ValueError("prepare_transition must have 'd' object")
    pv = d.get("protocol_version")
    tid = d.get("transition_id")
    if pv is None or tid is None:
        raise ValueError("protocol_version and transition_id required")
    try:
        pv, tid = int(pv), int(tid)
    except (TypeError, ValueError):
        raise ValueError("protocol_version and transition_id must be integers") from None
    if not 0 <= tid <= 0xFFFF:
        raise ValueError("transition_id must be uint16")
    return pv, tid


def parse_execute_transition(payload: bytes) -> int:
    """
    Parse opcode 22 (Execute Transition) JSON payload.

    Args:
        payload (bytes): UTF-8 JSON e.g. {"op": 22, "d": {"transition_id": 10}}.

    Returns:
        int: transition_id for session.execute_transition(transition_id).

    Raises:
        ValueError: If JSON invalid, missing d.transition_id, or transition_id out of uint16 range.
    """
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError("Invalid execute transition payload") from e
    if not isinstance(obj, dict):
        raise ValueError("Execute transition payload must be a JSON object")
    d = obj.get("d")
    if not isinstance(d, dict):
        raise ValueError("Execute transition payload must have 'd' object")
    tid = d.get("transition_id")
    if tid is None:
        raise ValueError("Execute transition payload must have d.transition_id")
    try:
        tid = int(tid)
    except (TypeError, ValueError):
        raise ValueError("d.transition_id must be an integer") from None
    if not 0 <= tid <= 0xFFFF:
        raise ValueError("transition_id must be uint16")
    return tid


def build_ready_for_transition(transition_id: int) -> bytes:
    """
    Build opcode 23 (Ready For Transition) JSON payload. Client sends to server.

    Args:
        transition_id (int): Transition ID (uint16) the client is ready to execute.

    Returns:
        bytes: UTF-8 JSON payload, e.g. {"op":23,"d":{"transition_id":10}}.

    Raises:
        ValueError: If transition_id not in 0..65535.
    """
    if not 0 <= transition_id <= 0xFFFF:
        raise ValueError("transition_id must be uint16")
    obj = {"op": OPCODE_READY_FOR_TRANSITION, "d": {"transition_id": transition_id}}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def parse_prepare_epoch(payload: bytes) -> tuple[int, int]:
    """
    Parse opcode 24 (Prepare Epoch) JSON payload. Server sends to client.

    Args:
        payload (bytes): UTF-8 JSON with "d.protocol_version" and "d.epoch".

    Returns:
        tuple[int, int]: (protocol_version, epoch). epoch 1 = new MLS group to be created.

    Raises:
        ValueError: If JSON invalid or protocol_version/epoch missing or not integers.

    When to call: When the gateway tells the client to prepare an epoch; use epoch (e.g. 1)
    to call session.prepare_epoch(epoch).
    """
    obj = _parse_json_op(payload)
    d = obj.get("d")
    if not isinstance(d, dict):
        raise ValueError("prepare_epoch must have 'd' object")
    pv = d.get("protocol_version")
    epoch = d.get("epoch")
    if pv is None or epoch is None:
        raise ValueError("protocol_version and epoch required")
    try:
        pv, epoch = int(pv), int(epoch)
    except (TypeError, ValueError):
        raise ValueError("protocol_version and epoch must be integers") from None
    return pv, epoch


def build_invalid_commit_welcome(transition_id: int) -> bytes:
    """
    Build opcode 31 (Invalid Commit/Welcome) JSON payload.

    Send to voice gateway after catching InvalidCommitError; then call
    session.prepare_epoch(1) and send returned key package as opcode 26.

    Args:
        transition_id (int): Transition ID (uint16).

    Returns:
        bytes: UTF-8 JSON payload for opcode 31.

    Raises:
        ValueError: If transition_id not in uint16 range.
    """
    if not 0 <= transition_id <= 0xFFFF:
        raise ValueError("transition_id must be uint16")
    obj = {"op": OPCODE_INVALID_COMMIT_WELCOME, "d": {"transition_id": transition_id}}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")
