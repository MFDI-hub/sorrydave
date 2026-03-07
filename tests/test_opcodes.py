"""Tests for DAVE Voice Gateway opcode parsing and building (opcodes 22, 25-31)."""

import json
import struct

import pytest
from pydave.mls.opcodes import (
    OPCODE_ANNOUNCE_COMMIT,
    OPCODE_EXECUTE_TRANSITION,
    OPCODE_EXTERNAL_SENDER_PACKAGE,
    OPCODE_INVALID_COMMIT_WELCOME,
    OPCODE_KEY_PACKAGE,
    OPCODE_PROPOSALS,
    OPCODE_WELCOME,
    build_commit_welcome,
    build_invalid_commit_welcome,
    build_key_package_message,
    parse_announce_commit,
    parse_execute_transition,
    parse_external_sender_package,
    parse_proposals,
    parse_welcome_message,
)


def _varint(n: int) -> bytes:
    """
    Encode nonnegative integer as MLS-style varint (for test payloads).

    Args:
        n (int): Nonnegative integer.

    Returns:
        bytes: Varint-encoded bytes.
    """
    buf = []
    while n >= 0x80:
        buf.append(0x80 | (n & 0x7F))
        n >>= 7
    buf.append(n & 0x7F)
    return bytes(buf)


# --- Opcode 22 (Execute Transition) ---


def test_parse_execute_transition_valid():
    payload = b'{"op":22,"d":{"transition_id":10}}'
    assert parse_execute_transition(payload) == 10
    assert parse_execute_transition(b'{"op": 22, "d": {"transition_id": 0}}') == 0
    assert parse_execute_transition(b'{"op": 22, "d": {"transition_id": 65535}}') == 65535


def test_parse_execute_transition_missing_d():
    """parse_execute_transition raises when 'd' object is missing."""
    with pytest.raises(ValueError, match="'d' object"):
        parse_execute_transition(b'{"op":22}')


def test_parse_execute_transition_missing_transition_id():
    """parse_execute_transition raises when d.transition_id is missing."""
    with pytest.raises(ValueError, match="transition_id"):
        parse_execute_transition(b'{"op":22,"d":{}}')


def test_parse_execute_transition_invalid_json():
    with pytest.raises(ValueError, match="Invalid execute transition"):
        parse_execute_transition(b"not json")
    with pytest.raises(ValueError, match="integer"):
        parse_execute_transition(b'{"op":22,"d":{"transition_id":"not_an_int"}}')


def test_parse_execute_transition_transition_id_out_of_range():
    """parse_execute_transition raises when transition_id is not uint16 (-1 or 65536)."""
    with pytest.raises(ValueError, match="uint16"):
        parse_execute_transition(b'{"op":22,"d":{"transition_id":-1}}')
    with pytest.raises(ValueError, match="uint16"):
        parse_execute_transition(b'{"op":22,"d":{"transition_id":65536}}')


# --- Opcode 31 (Invalid Commit/Welcome) ---


def test_build_invalid_commit_welcome_valid():
    """build_invalid_commit_welcome produces JSON with op 31 and d.transition_id."""
    out = build_invalid_commit_welcome(0)
    obj = json.loads(out.decode("utf-8"))
    assert obj["op"] == OPCODE_INVALID_COMMIT_WELCOME
    assert obj["d"]["transition_id"] == 0

    out = build_invalid_commit_welcome(32)
    obj = json.loads(out.decode("utf-8"))
    assert obj["d"]["transition_id"] == 32


def test_build_invalid_commit_welcome_out_of_range():
    """build_invalid_commit_welcome raises for transition_id outside uint16 range."""
    with pytest.raises(ValueError, match="uint16"):
        build_invalid_commit_welcome(-1)
    with pytest.raises(ValueError, match="uint16"):
        build_invalid_commit_welcome(65536)


# --- Opcode 25 (External Sender Package) ---


def test_parse_external_sender_package_minimal():
    """
    parse_external_sender_package parses minimal valid payload (seq 0, op 25, sig key, cred, identity).
    """
    # seq=0, opcode=25, sig_key length 2 + 2 bytes, cred_type=1, identity length 8 + 8 bytes
    sig_key = b"\x01\x02"
    identity = b"\x00\x00\x00\x00\x00\x00\x00\x01"
    payload = struct.pack("<HB", 0, 25) + _varint(2) + sig_key + struct.pack("!H", 1) + _varint(8) + identity
    p = parse_external_sender_package(payload)
    assert p.sequence_number == 0
    assert p.signature_key == sig_key
    assert p.credential_type == 1
    assert p.identity == identity


def test_parse_external_sender_package_wrong_opcode():
    """parse_external_sender_package raises when opcode is not 25."""
    payload = struct.pack("<HB", 0, 26) + _varint(0) + struct.pack("!H", 1) + _varint(0)
    with pytest.raises(ValueError, match="Expected opcode 25"):
        parse_external_sender_package(payload)


def test_parse_external_sender_package_too_short():
    """parse_external_sender_package raises when payload too short or truncated."""
    with pytest.raises(ValueError, match="too short"):
        parse_external_sender_package(b"\x00\x00")
    # 3 bytes passes length check but rest is empty -> varint truncated
    with pytest.raises(ValueError, match="truncated"):
        parse_external_sender_package(b"\x00\x00\x19")


# --- Opcode 26 (Key Package) ---


def test_build_key_package_message():
    """build_key_package_message prepends opcode 26 to key package bytes."""
    kp = b"fake_key_package_bytes"
    out = build_key_package_message(kp)
    assert out[0] == OPCODE_KEY_PACKAGE
    assert out[1:] == kp


# --- Opcode 27 (Proposals) ---


def test_parse_proposals_append_minimal():
    """parse_proposals with operation_type 0 (append) returns proposal_messages list."""
    # seq=1, opcode=27, op_type=0 (append), one proposal: len 3 + "abc"
    payload = struct.pack("<HBB", 1, 27, 0) + _varint(3) + b"abc"
    p = parse_proposals(payload)
    assert p.sequence_number == 1
    assert p.operation_type == 0
    assert p.proposal_messages == [b"abc"]
    assert p.proposal_refs is None


def test_parse_proposals_revoke():
    """parse_proposals with operation_type 1 (revoke) returns proposal_refs list."""
    ref = b"\x00\x01\x02"
    payload = struct.pack("<HBB", 2, 27, 1) + _varint(3) + ref
    p = parse_proposals(payload)
    assert p.operation_type == 1
    assert p.proposal_refs == [ref]
    assert p.proposal_messages is None


def test_parse_proposals_wrong_opcode():
    """parse_proposals raises when opcode is not 27."""
    payload = struct.pack("<HBB", 0, 28, 0)
    with pytest.raises(ValueError, match="Expected opcode 27"):
        parse_proposals(payload)


def test_parse_proposals_unknown_operation_type():
    """parse_proposals raises for unknown operation type (e.g. 99)."""
    payload = struct.pack("<HBB", 0, 27, 99)
    with pytest.raises(ValueError, match="Unknown proposals operation"):
        parse_proposals(payload)


# --- Opcode 28 (Commit/Welcome) ---


def test_build_commit_welcome_commit_only():
    """build_commit_welcome with welcome_message None produces opcode 28 and commit only."""
    commit = b"commit_bytes"
    out = build_commit_welcome(commit, None)
    assert out[0] == 28
    # Rest is varint(len(commit)) + commit
    assert commit in out


def test_build_commit_welcome_with_welcome():
    """build_commit_welcome with welcome message includes both commit and welcome in output."""
    commit = b"commit"
    welcome = b"welcome"
    out = build_commit_welcome(commit, welcome)
    assert out[0] == 28
    assert commit in out
    assert welcome in out


# --- Opcode 29 (Announce Commit) ---


def test_parse_announce_commit_minimal():
    """parse_announce_commit returns (transition_id, commit_bytes) for minimal payload."""
    # seq=0, opcode=29, transition_id=5, commit length 0
    payload = struct.pack("<HBH", 0, 29, 5) + _varint(0)
    tid, commit = parse_announce_commit(payload)
    assert tid == 5
    assert commit == b""


def test_parse_announce_commit_wrong_opcode():
    """parse_announce_commit raises when opcode is not 29."""
    payload = struct.pack("<H", 0) + bytes([30]) + struct.pack("<H", 0) + _varint(0)
    with pytest.raises(ValueError, match="Expected opcode 29"):
        parse_announce_commit(payload)


# --- Opcode 30 (Welcome) ---


def test_parse_welcome_message_minimal():
    """parse_welcome_message returns (transition_id, welcome_bytes) for minimal payload."""
    payload = struct.pack("<H", 0) + bytes([30]) + struct.pack("<H", 7) + _varint(0)
    tid, welcome = parse_welcome_message(payload)
    assert tid == 7
    assert welcome == b""


def test_parse_welcome_message_wrong_opcode():
    """parse_welcome_message raises when opcode is not 30."""
    payload = struct.pack("<H", 0) + bytes([29]) + struct.pack("<H", 0) + _varint(0)
    with pytest.raises(ValueError, match="Expected opcode 30"):
        parse_welcome_message(payload)
