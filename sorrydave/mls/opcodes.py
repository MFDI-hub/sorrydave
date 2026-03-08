"""
DAVE Voice Gateway opcode parsing and building (opcodes 22, 25-31).
Binary opcodes 25-30; JSON opcodes 22, 31. No I/O; consumes/produces bytes only.
"""

import json
import struct
from dataclasses import dataclass
from typing import Union

# Opcode values per protocol.md
OPCODE_EXECUTE_TRANSITION = 22
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
    elif op_type == 1:  # revoke
        refs = []
        off = 0
        while off < len(vector_bytes):
            ref, off = _read_opaque_varint(vector_bytes, off)
            refs.append(ref)
        return ProposalsMessage(sequence_number=seq, operation_type=1, proposal_refs=refs)


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
    Build opcode 28 payload: opcode || commit || optional welcome.

    Args:
        commit_message (bytes): Serialized MLS commit message.
        welcome_message (Union[bytes, None]): Optional serialized Welcome (not wrapped in MLSMessage).

    Returns:
        bytes: Opcode 28 message bytes.
    """
    out = bytes([OPCODE_COMMIT_WELCOME])
    out += commit_message
    if welcome_message:
        out += welcome_message  # Welcome is not wrapped in MLSMessage per DAVE struct
    return out


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


# --- JSON opcodes (22, 31) ---


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
