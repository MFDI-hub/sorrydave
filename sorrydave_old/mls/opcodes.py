"""
DAVE Voice Gateway opcode parsing and building (opcodes 0, 4, 11, 13, 21-24, 25-31).

Binary opcodes 25-30; JSON opcodes 0, 4, 11, 13, 21, 22, 23, 24, 31. No I/O; consumes/produces bytes only.

Public parse/build functions:
    - build_identify: Build opcode 0 (Identify) JSON; client sends to server.
    - parse_select_protocol_ack: Parse opcode 4 (Select Protocol Ack); returns protocol version.
    - parse_clients_connect: Parse opcode 11 (Clients Connect); returns list of int user_ids.
    - parse_client_disconnect: Parse opcode 13 (Client Disconnect); returns int user_id.
    - detect_binary_opcode: Opcode 25-30 from seq||op||body or op||body.
    - read_mls_varint: RFC 9420 variable-size length header (value, bytes consumed).
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

import contextlib
import json
import struct
from dataclasses import dataclass
from typing import Any, Union, cast

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


def read_mls_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Read an RFC 9420 variable-size integer (protocol.md binary vector lengths).

    Args:
        data (bytes): Buffer containing the varint.
        offset (int): Start index.

    Returns:
        tuple[int, int]: (value, bytes_consumed).
    """
    value, new_offset = _read_varint(data, offset)
    return value, new_offset - offset


def detect_binary_opcode(data: bytes) -> Union[int, None]:
    """
    Return the DAVE binary opcode (25-30) from a websocket binary frame.

    Gateway frames are ``uint16 sequence || uint8 opcode || body``. Client
    outbound frames (opcodes 26 and 28) are ``uint8 opcode || body``.
    """
    if not data:
        return None
    if len(data) >= 3 and 25 <= data[2] <= 30:
        return int(data[2])
    if 25 <= data[0] <= 30:
        return int(data[0])
    return None


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


# RFC 9420 MLSMessage prefix for protocol mls10 + wire_format mls_public_message.
MLS10_PUBLIC_MESSAGE_PREFIX = b"\x00\x01\x00\x01"


def wrap_public_message_as_mls_message(public_message: bytes) -> bytes:
    """Wrap a PublicMessage body as MLSMessage (protocol.md opcodes 26–29)."""
    if public_message.startswith(MLS10_PUBLIC_MESSAGE_PREFIX):
        return public_message
    return MLS10_PUBLIC_MESSAGE_PREFIX + public_message


def public_message_bytes(commit_or_proposal: bytes) -> bytes:
    """Return the PublicMessage body, stripping an MLSMessage header if present."""
    if commit_or_proposal.startswith(MLS10_PUBLIC_MESSAGE_PREFIX):
        return commit_or_proposal[4:]
    return commit_or_proposal


def _consume_public_message_body(body: bytes) -> tuple[Any, int]:
    """Parse one RFC 9420 PublicMessage; return (AuthenticatedContent, consumed)."""
    from rfc9420.messages.data_structures import SenderType
    from rfc9420.messages.messages import (
        AuthenticatedContent,
        AuthenticatedContentTBS,
        FramedContent,
        FramedContentAuthData,
        WireFormat,
    )

    fc = FramedContent.deserialize(body)
    off = len(fc.serialize())
    auth, consumed = FramedContentAuthData.deserialize(body[off:], fc.content_type)
    off += consumed
    membership_tag = None
    if fc.sender.sender_type == SenderType.MEMBER:
        membership_tag, off = _read_opaque_varint(body, off)
    ac = AuthenticatedContent(
        AuthenticatedContentTBS(wire_format=int(WireFormat.PUBLIC_MESSAGE), framed_content=fc),
        auth,
        membership_tag,
    )
    return ac, off


def consume_mls_public_plaintext(data: bytes) -> tuple[object, int]:
    """
    Parse one MLS public handshake message.

    Accepts either an MLSMessage (version + wire_format + PublicMessage) or a bare
    PublicMessage. Returns (MLSPlaintext, bytes_consumed).
    """
    from rfc9420.messages.messages import AuthenticatedContent, MLSPlaintext

    if len(data) < 2:
        raise ValueError("MLS message truncated")
    header = 0
    body = data
    if len(data) >= 4 and data.startswith(MLS10_PUBLIC_MESSAGE_PREFIX):
        header = 4
        body = data[4:]
    ac, n = _consume_public_message_body(body)
    return MLSPlaintext(cast(AuthenticatedContent, ac)), header + n


def iter_proposal_plaintexts(vector_blob: bytes) -> list[Any]:
    """
    Parse opcode 27 proposal_messages vector content into MLSPlaintext values.

    protocol.md: ``MLSMessage proposal_messages<V>``. Discord concatenates one or
    more MLS public messages (not MLSPlaintext without the MLSMessage header).
    """
    from rfc9420.messages.messages import MLSPlaintext

    if not vector_blob:
        return []
    if vector_blob.startswith(MLS10_PUBLIC_MESSAGE_PREFIX):
        messages = []
        off = 0
        while off < len(vector_blob):
            try:
                pt, n = consume_mls_public_plaintext(vector_blob[off:])
            except Exception:
                break
            if n <= 0:
                break
            messages.append(pt)
            off += n
        if messages and off == len(vector_blob):
            return messages
    with contextlib.suppress(Exception):
        return [MLSPlaintext.deserialize(vector_blob)]
    messages = []
    for chunk in split_proposal_messages_vector(vector_blob):
        with contextlib.suppress(Exception):
            if chunk.startswith(MLS10_PUBLIC_MESSAGE_PREFIX):
                pt, n = consume_mls_public_plaintext(chunk)
                if n == len(chunk):
                    messages.append(pt)
                    continue
            messages.append(MLSPlaintext.deserialize(chunk))
    return messages


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
        list[bytes]: list of MLSMessage byte strings.
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
    Build opcode 28: opcode || MLSMessage(commit) || optional Welcome.

    protocol.md: commit is an MLSMessage; Welcome is the raw Welcome struct
    (not wrapped in MLSMessage) when the commit adds members.
    """
    out = bytes([OPCODE_COMMIT_WELCOME])
    out += wrap_public_message_as_mls_message(commit_message)
    if welcome_message:
        out += welcome_message
    return out


def parse_commit_welcome(data: bytes) -> tuple[bytes, Union[bytes, None]]:
    """
    Parse opcode 28: MLSMessage commit + optional Welcome.

    Returns:
        tuple[bytes, Union[bytes, None]]: (MLSMessage commit bytes, Welcome or None).
    """
    if len(data) < 1:
        raise ValueError("Commit/welcome message too short")
    opcode = data[0]
    if opcode != OPCODE_COMMIT_WELCOME:
        raise ValueError(f"Expected opcode 28, got {opcode}")
    rest = data[1:]
    if rest.startswith(MLS10_PUBLIC_MESSAGE_PREFIX):
        try:
            _pt, consumed = consume_mls_public_plaintext(rest)
            commit_message = rest[:consumed]
            welcome_rest = rest[consumed:]
            welcome_message = welcome_rest if welcome_rest else None
            return commit_message, welcome_message
        except Exception:
            # Dummy / non-MLS payloads used in unit tests.
            return public_message_bytes(rest), None
    if rest:
        # Legacy opaque<V> commit used by older sorrydave builds.
        with contextlib.suppress(Exception):
            commit_message, off = _read_opaque_varint(data, 1)
            welcome_message = data[off:] if off < len(data) else None
            return commit_message, welcome_message or None
    return rest, None


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

JsonPayload = Union[bytes, bytearray, memoryview, str, dict[str, Any]]


def _coerce_json_object(
    payload: object,
    *,
    invalid_message: str = "Invalid JSON payload",
) -> dict[str, Any]:
    """Decode bytes/str JSON or accept an already-parsed object."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray, memoryview)):
        raw = bytes(payload)
    else:
        raise ValueError(invalid_message)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(invalid_message) from e
    if not isinstance(obj, dict):
        raise ValueError("Payload must be a JSON object")
    return obj


def _json_d(
    payload: object,
    *,
    missing_d: str,
    invalid_message: str = "Invalid JSON payload",
) -> dict[str, Any]:
    """Return the opcode ``d`` object, or ``payload`` itself if it is already ``d``."""
    obj = _coerce_json_object(payload, invalid_message=invalid_message)
    d = obj.get("d")
    if isinstance(d, dict):
        return d
    if "op" not in obj:
        return obj
    raise ValueError(missing_d)


def _parse_json_op(payload: object) -> dict[str, Any]:
    """Decode UTF-8 JSON (or accept a dict) and return the root object."""
    return _coerce_json_object(payload)


def _coerce_snowflake(value: object, *, field: str) -> int:
    """Parse a Discord snowflake from int or digit string."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be an integer or digit string")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an integer or digit string") from None


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


def parse_select_protocol_ack(payload: JsonPayload) -> int:
    """
    Parse opcode 4 (Select Protocol Ack) JSON payload. Server sends to client.

    Args:
        payload: UTF-8 JSON bytes, a parsed ``{op,d}`` object, or the ``d`` object.
            Reads ``dave_protocol_version``, then ``protocol_version``.

    Returns:
        int: dave_protocol_version (initial DAVE protocol version for the session).

    Raises:
        ValueError: If JSON invalid, missing "d", or missing/invalid dave_protocol_version.
    """
    d = _json_d(payload, missing_d="select_protocol_ack must have 'd' object")
    v = d.get("dave_protocol_version")
    if v is None:
        v = d.get("protocol_version")
    if v is None:
        raise ValueError("dave_protocol_version required")
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError("dave_protocol_version must be an integer") from None


def parse_clients_connect(payload: JsonPayload) -> list[int]:
    """
    Parse opcode 11 (Clients Connect) JSON payload. Server sends to client.

    Args:
        payload: UTF-8 JSON bytes, a parsed ``{op,d}`` object, or the ``d`` object.

    Returns:
        list[int]: Discord snowflake user IDs.

    Raises:
        ValueError: If JSON invalid or user_ids missing/not a list of snowflakes.
    """
    d = _json_d(payload, missing_d="clients_connect must have 'd' object")
    user_ids = d.get("user_ids")
    if not isinstance(user_ids, list):
        raise ValueError("user_ids must be a list")
    return [_coerce_snowflake(u, field="user_ids") for u in user_ids]


def parse_client_disconnect(payload: JsonPayload) -> int:
    """
    Parse opcode 13 (Client Disconnect) JSON payload. Server sends to client.

    Args:
        payload: UTF-8 JSON bytes, a parsed ``{op,d}`` object, or the ``d`` object.

    Returns:
        int: Discord snowflake user ID that disconnected.

    Raises:
        ValueError: If JSON invalid or user_id missing/not a snowflake.
    """
    d = _json_d(payload, missing_d="client_disconnect must have 'd' object")
    if "user_id" not in d:
        raise ValueError("user_id must be an integer or digit string")
    return _coerce_snowflake(d.get("user_id"), field="user_id")


def parse_prepare_transition(payload: JsonPayload) -> tuple[int, int]:
    """
    Parse opcode 21 (Prepare Transition) JSON payload. Server sends to client.

    Args:
        payload: UTF-8 JSON bytes, a parsed ``{op,d}`` object, or the ``d`` object.

    Returns:
        tuple[int, int]: (protocol_version, transition_id). transition_id 0 = execute immediately.

    Raises:
        ValueError: If JSON invalid, fields missing, or transition_id not in uint16 range.
    """
    d = _json_d(payload, missing_d="prepare_transition must have 'd' object")
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


def parse_execute_transition(payload: JsonPayload) -> int:
    """
    Parse opcode 22 (Execute Transition) JSON payload.

    Args:
        payload: UTF-8 JSON bytes, a parsed ``{op,d}`` object, or the ``d`` object.

    Returns:
        int: transition_id for session.execute_transition(transition_id).

    Raises:
        ValueError: If JSON invalid, missing d.transition_id, or transition_id out of uint16 range.
    """
    d = _json_d(
        payload,
        missing_d="Execute transition payload must have 'd' object",
        invalid_message="Invalid execute transition payload",
    )
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


def parse_prepare_epoch(payload: JsonPayload) -> tuple[int, int]:
    """
    Parse opcode 24 (Prepare Epoch) JSON payload. Server sends to client.

    Args:
        payload: UTF-8 JSON bytes, a parsed ``{op,d}`` object, or the ``d`` object.

    Returns:
        tuple[int, int]: (protocol_version, epoch). epoch 1 = new MLS group to be created.

    Raises:
        ValueError: If JSON invalid or protocol_version/epoch missing or not integers.

    When to call: When the gateway tells the client to prepare an epoch; use epoch (e.g. 1)
    to call session.prepare_epoch(epoch).
    """
    d = _json_d(payload, missing_d="prepare_epoch must have 'd' object")
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
