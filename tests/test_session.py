"""Integration-style tests for DaveSession."""

import struct

import pytest
from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.opcodes import build_invalid_commit_welcome
from sorrydave.session import DaveSession


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


def _make_minimal_external_sender_package() -> bytes:
    """Minimal valid opcode 25 payload for testing."""
    sig_key = b"\x01\x02"
    identity = (123456789).to_bytes(8, "big")
    payload = (
        struct.pack("<HB", 0, 25)
        + _varint(2)
        + sig_key
        + struct.pack("!H", 1)
        + _varint(8)
        + identity
    )
    return payload


def test_session_prepare_epoch_1_returns_key_package_payload():
    """prepare_epoch(1) returns opcode 26 key package payload."""
    session = DaveSession(local_user_id=111)
    out = session.prepare_epoch(1)
    assert out is not None
    assert isinstance(out, bytes)
    assert len(out) > 0
    assert out[0] == 26  # OPCODE_KEY_PACKAGE


def test_session_prepare_epoch_non_one_returns_none():
    session = DaveSession(local_user_id=111)
    assert session.prepare_epoch(0) is None
    assert session.prepare_epoch(2) is None


def test_session_handle_external_sender_package_creates_group_and_encryptor():
    """After external sender package and key package, get_encryptor works and encrypt produces DAVE magic."""
    session = DaveSession(local_user_id=222)
    session.prepare_epoch(1)
    pkg = _make_minimal_external_sender_package()
    session.handle_external_sender_package(pkg)
    enc = session.get_encryptor()
    frame = enc.encrypt(b"hello", codec="OPUS")
    assert isinstance(frame, bytes)
    assert len(frame) > len(b"hello")
    assert frame[-2:] == b"\xfa\xfa"  # DAVE magic


def test_session_uses_channel_id_as_mls_group_id():
    """Local group is created with channel_id as 8-byte big-endian MLS group ID."""
    from sorrydave.session import mls_group_id_from_channel_id

    channel_id = 1043272195868217368
    session = DaveSession(local_user_id=222, channel_id=channel_id)
    session.prepare_epoch(1)
    session.handle_external_sender_package(_make_minimal_external_sender_package())
    expected = mls_group_id_from_channel_id(channel_id)
    assert session.group_id == expected
    assert session._group is not None
    assert session._group.group_id == expected


def test_session_execute_transition_no_op():
    """execute_transition can be called without error; encryptor still works."""
    session = DaveSession(local_user_id=333)
    session.prepare_epoch(1)
    session.handle_external_sender_package(_make_minimal_external_sender_package())
    session.execute_transition(0)
    enc = session.get_encryptor()
    enc.encrypt(b"x", codec="OPUS")


def test_session_handle_commit_invalid_raises():
    """handle_commit with no group raises InvalidCommitError."""
    session = DaveSession(local_user_id=444)
    with pytest.raises(InvalidCommitError, match="No group"):
        session.handle_commit(0, b"invalid_commit_bytes")


def test_session_foreign_initial_commit_waits_for_welcome():
    """A losing epoch-0 committer discards candidates and waits for op30."""
    session = DaveSession(local_user_id=445)
    session._group = object()
    session._outbound_staged_commits[b"own-candidate"] = object()
    session._initial_commit_bytes = b"own-candidate"

    session.handle_commit(0, b"foreign-candidate")

    assert session._current_epoch == 0
    assert session._outbound_staged_commits == {}
    assert session._initial_commit_bytes is None


def test_session_foreign_commit_without_own_candidate_waits_for_welcome():
    """Pending joiners have no staged commit; foreign op29 still must not apply."""
    session = DaveSession(local_user_id=446)
    session._group = object()

    session.handle_commit(0, b"established-group-commit")

    assert session._current_epoch == 0
    assert session._outbound_staged_commits == {}
    assert session.is_media_ready is False


def test_session_error_recovery_opcode_31_and_prepare_epoch():
    """After InvalidCommitError, app can build opcode 31 and call prepare_epoch(1)."""
    transition_id = 5
    payload_31 = build_invalid_commit_welcome(transition_id)
    assert payload_31 is not None
    assert b"transition_id" in payload_31
    session = DaveSession(local_user_id=555)
    kp_payload = session.prepare_epoch(1)
    assert kp_payload is not None
    assert kp_payload[0] == 26


def test_session_leave_group_clears_state_and_returns_none():
    """leave_group clears state and returns None (opcode 27 is gateway-to-client only)."""
    session = DaveSession(local_user_id=666)
    session.prepare_epoch(1)
    session.handle_external_sender_package(_make_minimal_external_sender_package())
    assert session.leave_group() is None
    with pytest.raises(RuntimeError, match="No send ratchet"):
        session.get_encryptor()


def test_session_leave_group_no_group_returns_none():
    """leave_group when no group was established returns None."""
    session = DaveSession(local_user_id=777)
    assert session.leave_group() is None
