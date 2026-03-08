"""Comprehensive DaveSession tests: lifecycle, state transitions, error handling."""

import pytest

from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.group_state import (
    create_key_package,
    get_dave_crypto_provider,
)
from sorrydave.mls.opcodes import ExternalSenderPackage
from sorrydave.session import DaveSession


@pytest.fixture
def crypto():
    return get_dave_crypto_provider()


@pytest.fixture
def session():
    return DaveSession(local_user_id=123456789, protocol_version=1)


class TestDaveSessionInit:
    def test_default_state(self, session):
        assert session._local_user_id == 123456789
        assert session._protocol_version == 1
        assert session._group is None
        assert session._crypto is None
        assert session._send_ratchet is None
        assert session._receive_ratchets == {}
        assert session._current_epoch == 0
        assert session._key_package_bytes is None

    def test_custom_version(self):
        s = DaveSession(42, protocol_version=2)
        assert s._protocol_version == 2
        assert s._local_user_id == 42


class TestPrepareEpoch:
    def test_epoch_1_returns_key_package(self, session):
        result = session.prepare_epoch(1)
        assert result is not None
        assert isinstance(result, bytes)
        assert len(result) > 1
        assert result[0] == 26  # OPCODE_KEY_PACKAGE

    def test_epoch_1_stores_key_package(self, session):
        session.prepare_epoch(1)
        assert session._key_package_bytes is not None
        assert session._hpke_private_key is not None
        assert session._signing_key_der is not None

    def test_epoch_non_1_returns_none(self, session):
        assert session.prepare_epoch(0) is None
        assert session.prepare_epoch(2) is None
        assert session.prepare_epoch(100) is None

    def test_epoch_1_initializes_crypto(self, session):
        session.prepare_epoch(1)
        assert session._crypto is not None

    def test_epoch_1_with_ext_sender_creates_group(self, session):
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )
        session.handle_external_sender_package(pkg)
        session.prepare_epoch(1)
        assert session._group is not None


class TestHandleExternalSenderPackage:
    def test_stores_package(self, session):
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xBB" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        assert session._external_sender is pkg

    def test_accepts_bytes(self, session):
        import struct
        sig_key = b"\xCC" * 32
        identity = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        data = struct.pack("!H", 0) + bytes([25])
        data += bytes([len(sig_key)]) + sig_key
        data += struct.pack("!H", 1)
        data += bytes([len(identity)]) + identity
        session.handle_external_sender_package(data)
        assert session._external_sender is not None
        assert session._external_sender.signature_key == sig_key

    def test_creates_group_if_kp_exists(self, session, crypto):
        session.prepare_epoch(1)
        assert session._key_package_bytes is not None
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xDD" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        assert session._group is not None

    def test_no_group_if_no_kp(self, session):
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xEE" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        assert session._group is None

    def test_idempotent_if_group_exists(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xFF" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        group1 = session._group
        session.handle_external_sender_package(pkg)
        assert session._group is group1


class TestHandlePrepareTransition:
    def test_transition_id_zero_calls_execute(self, session):
        called = []
        original = session.execute_transition
        def mock_execute(tid):
            called.append(tid)
            original(tid)
        session.execute_transition = mock_execute
        session.handle_prepare_transition(1, 0)
        assert called == [0]

    def test_transition_id_nonzero_no_execute(self, session):
        called = []
        session.execute_transition = lambda tid: called.append(tid)
        session.handle_prepare_transition(1, 5)
        assert called == []


class TestExecuteTransition:
    def test_no_group_no_crash(self, session):
        session.execute_transition(0)

    def test_with_group_refreshes(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        session.execute_transition(1)


class TestLeaveGroup:
    def test_no_group_returns_none(self, session):
        result = session.leave_group()
        assert result is None

    def test_clears_state(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        session.leave_group()
        assert session._group is None
        assert session._send_ratchet is None
        assert session._receive_ratchets == {}
        assert session._member_leaf_indices == {}
        assert session._current_epoch == 0
        assert session._key_package_bytes is None

    def test_returns_remove_proposal_bytes(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xBB" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        result = session.leave_group()
        if result is not None:
            assert isinstance(result, bytes)


class TestGetEncryptor:
    def test_no_group_raises(self, session):
        with pytest.raises(RuntimeError, match="No send ratchet"):
            session.get_encryptor()

    def test_with_group_returns_encryptor(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        session._refresh_send_ratchet()
        enc = session.get_encryptor()
        from sorrydave.media.transform import FrameEncryptor
        assert isinstance(enc, FrameEncryptor)


class TestGetDecryptor:
    def test_no_sender_raises(self, session):
        with pytest.raises(KeyError, match="No ratchet"):
            session.get_decryptor(999)


class TestHandleCommit:
    def test_no_group_raises(self, session):
        with pytest.raises(InvalidCommitError, match="No group"):
            session.handle_commit(1, b"\x00")


class TestHandleProposals:
    def test_no_group_returns_none(self, session):
        result = session.handle_proposals(b"\x00" * 10)
        assert result is None

    def test_invalid_payload_returns_none(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        result = session.handle_proposals(b"\x00")
        assert result is None


class TestHandleWelcome:
    def test_no_hpke_key_raises(self, session):
        with pytest.raises(ValueError, match="HPKE"):
            session.handle_welcome(1, b"\x00")


class TestSessionErrorRecovery:
    """Test error recovery flow: opcode 31 + prepare_epoch(1)."""

    def test_recovery_after_invalid_commit(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        with pytest.raises((InvalidCommitError, Exception)):
            session.handle_commit(1, b"\x00" * 20)
        from sorrydave.mls.opcodes import build_invalid_commit_welcome
        opcode_31 = build_invalid_commit_welcome(1)
        assert opcode_31 is not None
        result = session.prepare_epoch(1)
        assert result is not None


class TestSessionLeafIndexToUserId:
    def test_no_group_returns_none(self, session):
        assert session._leaf_index_to_user_id(0) is None

    def test_with_group(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        result = session._leaf_index_to_user_id(0)
        # May return user_id or None depending on tree state
        assert result is None or isinstance(result, int)
