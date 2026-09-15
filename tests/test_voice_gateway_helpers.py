"""Transport-free Voice Gateway facade: parse-and-apply without I/O or op22."""

from __future__ import annotations

import struct

import pytest
from sorrydave import (
    PREPARE_DEFER_UNTIL_MEDIA_READY,
    PREPARE_EXECUTE_NOW,
    PREPARE_WAIT_FOR_EXECUTE,
    DaveSession,
    apply_proposals_message,
    configure_occupied_join,
    handle_announce_commit_wire,
    handle_execute_transition_message,
    handle_external_sender_wire,
    handle_prepare_transition_message,
    handle_welcome_wire,
    recover_invalid_commit,
    sync_client_disconnect,
    sync_clients_connect,
)
from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.opcodes import (
    ExternalSenderPackage,
    build_invalid_commit_welcome_dict,
    build_ready_for_transition_dict,
)
from sorrydave.session import PREPARE_DEFER_UNTIL_MEDIA_READY as SESSION_DEFER


def _mls_varint(n: int) -> bytes:
    if n <= 0x3F:
        return bytes([n])
    if n <= 0x3FFF:
        return bytes([0x40 | (n >> 8), n & 0xFF])
    raise ValueError("value too large for test varint")


def _external_sender_wire(user_id: int = 123456789) -> bytes:
    sig_key = b"\xaa" * 32
    identity = int(user_id).to_bytes(8, "big")
    return (
        struct.pack("!HB", 0, 25)
        + _mls_varint(len(sig_key))
        + sig_key
        + struct.pack("!H", 1)
        + _mls_varint(len(identity))
        + identity
    )


def _announce_frame(transition_id: int, commit: bytes = b"\x00\x01\x00\x01dummy") -> bytes:
    return struct.pack("!HBH", 1, 29, transition_id) + commit


def _welcome_frame(transition_id: int, welcome: bytes = b"\x00") -> bytes:
    return struct.pack("!HBH", 1, 30, transition_id) + welcome


def _proposals_append_frame(sequence: int = 1, blob: bytes = b"abc") -> bytes:
    return struct.pack("!HBB", sequence, 27, 0) + _mls_varint(len(blob)) + blob


def _pending_group_session(user_id: int = 111) -> DaveSession:
    session = DaveSession(local_user_id=user_id, channel_id=123)
    session.prepare_epoch(1)
    session.handle_external_sender_package(_external_sender_wire())
    return session


class TestClientsConnectDisconnect:
    def test_sync_clients_connect_registers_expected(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        ids = sync_clients_connect(session, {"op": 11, "d": {"user_ids": ["8", 9]}})
        assert ids == [8, 9]
        assert configure_occupied_join(session) is True
        assert session.take_commit_welcome() is None

    def test_sync_client_disconnect_removes_expected(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        sync_clients_connect(session, {"d": {"user_ids": [8]}})
        uid = sync_client_disconnect(session, {"op": 13, "d": {"user_id": "8"}})
        assert uid == 8
        assert session.configure_occupied_join() is False

    def test_malformed_clients_connect_raises(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        with pytest.raises(ValueError):
            sync_clients_connect(session, {"op": 11, "d": {}})


class TestPrepareAndExecute:
    def test_prepare_defers_tid0_until_media_ready(self):
        session = DaveSession(local_user_id=1, channel_id=1)
        result = handle_prepare_transition_message(
            session, {"op": 21, "d": {"protocol_version": 1, "transition_id": 0}}
        )
        assert result.action == PREPARE_DEFER_UNTIL_MEDIA_READY
        assert result.action == SESSION_DEFER
        assert result.transition_id == 0
        assert result.media_ready is False

    def test_prepare_nonzero_waits_for_opcode_22(self):
        session = _pending_group_session()
        session._current_epoch = 1
        session._refresh_send_ratchet()
        result = handle_prepare_transition_message(
            session, {"d": {"protocol_version": 1, "transition_id": 8}}
        )
        assert result.action == PREPARE_WAIT_FOR_EXECUTE
        assert session.get_pending_transition() == (8, 1)

    def test_prepare_tid0_executes_when_ready(self):
        session = _pending_group_session()
        session._current_epoch = 1
        session._refresh_send_ratchet()
        result = handle_prepare_transition_message(
            session, {"op": 21, "d": {"protocol_version": 1, "transition_id": 0}}
        )
        assert result.action == PREPARE_EXECUTE_NOW
        assert result.media_ready is True

    def test_execute_transition_message(self):
        session = _pending_group_session()
        session._current_epoch = 1
        session._refresh_send_ratchet()
        handle_prepare_transition_message(
            session, {"d": {"protocol_version": 1, "transition_id": 4}}
        )
        tid = handle_execute_transition_message(session, {"op": 22, "d": {"transition_id": 4}})
        assert tid == 4
        assert session.get_pending_transition() is None


class TestExternalSenderAndProposals:
    def test_handle_external_sender_wire(self):
        session = DaveSession(local_user_id=111, channel_id=123)
        session.prepare_epoch(1)
        pkg = handle_external_sender_wire(session, _external_sender_wire())
        assert isinstance(pkg, ExternalSenderPackage)
        assert pkg.credential_type == 1
        assert session.current_epoch == 0

    def test_apply_proposals_malformed_raises(self):
        session = _pending_group_session()
        with pytest.raises(ValueError):
            apply_proposals_message(session, b"\x00\x01")

    def test_apply_proposals_dummy_append_does_not_commit(self):
        session = _pending_group_session()
        result = apply_proposals_message(session, _proposals_append_frame())
        assert result.sequence_number == 1
        assert result.operation_type == 0
        assert result.should_commit is False
        assert session.take_commit_welcome() is None


class TestCommitWelcomeWire:
    def test_foreign_op29_at_epoch_zero_is_not_applied(self):
        session = _pending_group_session()
        executed: list[int] = []
        session.execute_transition = lambda tid: executed.append(tid)  # type: ignore[method-assign]
        result = handle_announce_commit_wire(session, _announce_frame(3))
        assert result.transition_id == 3
        assert result.applied is False
        assert result.media_ready is False
        assert executed == []
        assert session.current_epoch == 0

    def test_announce_applied_when_epoch_advances(self, monkeypatch: pytest.MonkeyPatch):
        session = _pending_group_session()

        def _apply(_tid: int, _commit: bytes) -> None:
            session._current_epoch += 1
            session._refresh_send_ratchet()

        monkeypatch.setattr(session, "handle_commit", _apply)
        executed: list[int] = []
        monkeypatch.setattr(session, "execute_transition", lambda tid: executed.append(tid))
        result = handle_announce_commit_wire(session, _announce_frame(7))
        assert result.applied is True
        assert result.transition_id == 7
        assert result.media_ready is True
        assert executed == []

    def test_welcome_invalid_raises_invalid_commit(self):
        session = _pending_group_session()
        with pytest.raises(InvalidCommitError):
            handle_welcome_wire(session, _welcome_frame(5, b"\x00"))
        assert session.current_epoch == 0

    def test_malformed_announce_raises(self):
        session = _pending_group_session()
        with pytest.raises(ValueError):
            handle_announce_commit_wire(session, b"\x00")


class TestOccupiedJoinAndRecovery:
    def test_occupied_join_helper(self):
        session = _pending_group_session()
        assert configure_occupied_join(session, [222]) is True
        assert session.take_commit_welcome() is None

    def test_recover_invalid_commit_payloads(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        session.prepare_epoch(1)
        recovery = recover_invalid_commit(session, 12)
        assert recovery.transition_id == 12
        assert recovery.op31 == build_invalid_commit_welcome_dict(12)
        assert recovery.key_package[0] == 26
        assert session.current_epoch == 0


class TestReadyDict:
    def test_ready_dict_shape(self):
        payload = build_ready_for_transition_dict(10)
        assert payload == {"op": 23, "d": {"transition_id": 10}}
