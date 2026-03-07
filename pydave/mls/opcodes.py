"""
DAVE Voice Gateway binary opcode parsing (opcodes 25-30).
No I/O; consumes/produces bytes only.
"""

import struct
from dataclasses import dataclass
from typing import Optional

# Opcode values per protocol.md
OPCODE_EXTERNAL_SENDER_PACKAGE = 25
OPCODE_KEY_PACKAGE = 26
OPCODE_PROPOSALS = 27
OPCODE_COMMIT_WELCOME = 28
OPCODE_ANNOUNCE_COMMIT = 29
OPCODE_WELCOME = 30

# MLS variable-length encoding: length prefix per RFC 9420 §2.1.2 (varint)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read MLS-style varint (variable-size length); return (value, new_offset)."""
    n = 0
    shift = 0
    pos = offset
    while pos < len(data):
        b = data[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, pos
        shift += 7
        if shift >= 35:
            raise ValueError("Varint overflow")
    raise ValueError("Varint truncated")


def _read_opaque_varint(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read opaque<V>: varint length then that many bytes."""
    length, pos = _read_varint(data, offset)
    if pos + length > len(data):
        raise ValueError("Opaque truncated")
    return data[pos : pos + length], pos + length


@dataclass(slots=True)
class ExternalSenderPackage:
    """Parsed opcode 25: external sender credential and signature key."""

    sequence_number: int
    signature_key: bytes
    credential_type: int
    identity: bytes


def parse_external_sender_package(data: bytes) -> ExternalSenderPackage:
    """Parse DAVE_MLSExternalSenderPackage (opcode 25)."""
    if len(data) < 2 + 1:
        raise ValueError("External sender package too short")
    (seq,) = struct.unpack("<H", data[:2])
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
    """Build opcode 26 payload: opcode (1) || MLSMessage (key package)."""
    return bytes([OPCODE_KEY_PACKAGE]) + key_package_bytes


@dataclass(slots=True)
class ProposalsMessage:
    """Parsed opcode 27: append (proposal messages) or revoke (proposal refs)."""

    sequence_number: int
    operation_type: int  # 0 = append, 1 = revoke
    proposal_messages: Optional[list[bytes]] = None
    proposal_refs: Optional[list[bytes]] = None


def parse_proposals(data: bytes) -> ProposalsMessage:
    """Parse DAVE_MLSProposals (opcode 27)."""
    if len(data) < 2 + 1 + 1:
        raise ValueError("Proposals message too short")
    (seq,) = struct.unpack("<H", data[:2])
    opcode = data[2]
    if opcode != OPCODE_PROPOSALS:
        raise ValueError(f"Expected opcode 27, got {opcode}")
    op_type = data[3]
    rest = data[4:]
    if op_type == 0:  # append
        messages = []
        off = 0
        while off < len(rest):
            msg, off = _read_opaque_varint(rest, off)
            messages.append(msg)
        return ProposalsMessage(sequence_number=seq, operation_type=0, proposal_messages=messages)
    elif op_type == 1:  # revoke
        refs = []
        off = 0
        while off < len(rest):
            ref, off = _read_opaque_varint(rest, off)
            refs.append(ref)
        return ProposalsMessage(sequence_number=seq, operation_type=1, proposal_refs=refs)
    else:
        raise ValueError(f"Unknown proposals operation type {op_type}")


def parse_announce_commit(data: bytes) -> tuple[int, bytes]:
    """Parse opcode 29: transition_id (uint16) + MLSMessage commit."""
    if len(data) < 2 + 1 + 2:
        raise ValueError("Announce commit too short")
    (seq,) = struct.unpack("<H", data[:2])
    opcode = data[2]
    if opcode != OPCODE_ANNOUNCE_COMMIT:
        raise ValueError(f"Expected opcode 29, got {opcode}")
    (transition_id,) = struct.unpack("<H", data[3:5])
    commit_message, _ = _read_opaque_varint(data, 5)
    return transition_id, commit_message


def parse_welcome_message(data: bytes) -> tuple[int, bytes]:
    """Parse opcode 30: transition_id (uint16) + Welcome."""
    if len(data) < 2 + 1 + 2:
        raise ValueError("Welcome message too short")
    (seq,) = struct.unpack("<H", data[:2])
    opcode = data[2]
    if opcode != OPCODE_WELCOME:
        raise ValueError(f"Expected opcode 30, got {opcode}")
    (transition_id,) = struct.unpack("<H", data[3:5])
    welcome_bytes, _ = _read_opaque_varint(data, 5)
    return transition_id, welcome_bytes


def build_commit_welcome(commit_message: bytes, welcome_message: Optional[bytes]) -> bytes:
    """Build opcode 28 payload: opcode || commit || optional welcome."""
    out = bytes([OPCODE_COMMIT_WELCOME])
    # MLSMessage commit
    out += _write_opaque_varint(commit_message)
    if welcome_message:
        out += welcome_message  # Welcome is not wrapped in MLSMessage per DAVE struct
    return out


def _write_opaque_varint(data: bytes) -> bytes:
    """Write varint length prefix then data."""
    n = len(data)
    buf = []
    while n >= 0x80:
        buf.append(0x80 | (n & 0x7F))
        n >>= 7
    buf.append(n & 0x7F)
    return bytes(buf) + data
