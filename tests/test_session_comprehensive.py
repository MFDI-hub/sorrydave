"""Comprehensive DaveSession tests: lifecycle, state transitions, error handling."""

from types import SimpleNamespace

import pytest
from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.group_state import (
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
        assert session._expected_member_ids == {123456789}
        assert session.group_id == b"dave-default-group"
        assert session.channel_id is None

    def test_custom_version(self):
        s = DaveSession(42, protocol_version=2)
        assert s._protocol_version == 2
        assert s._local_user_id == 42

    def test_channel_id_sets_mls_group_id(self):
        channel_id = 1043272195868217368
        s = DaveSession(local_user_id=1, channel_id=channel_id)
        assert s.channel_id == channel_id
        assert s.group_id == channel_id.to_bytes(8, "big")
        assert len(s.group_id) == 8

    def test_channel_id_accepts_string_snowflake(self):
        s = DaveSession(local_user_id=1, channel_id="1043272195868217368")
        assert s.channel_id == 1043272195868217368
        assert s.group_id == (1043272195868217368).to_bytes(8, "big")

    def test_group_id_setter_accepts_snowflake_int(self):
        s = DaveSession(local_user_id=1)
        s.group_id = 1043272195868217368
        assert s.group_id == (1043272195868217368).to_bytes(8, "big")
        assert s.channel_id == 1043272195868217368

    def test_explicit_group_id_bytes_override_channel_id(self):
        raw = b"custom-id"
        s = DaveSession(local_user_id=1, channel_id=99, group_id=raw)
        assert s.group_id == raw


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

    def test_creates_group_if_kp_exists(self, session, crypto):  # noqa: ARG002
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

    def test_downgrade_prepare_enables_receive_passthrough(self, session):
        session.handle_prepare_transition(0, 7)
        assert session._receive_passthrough is True
        assert session._send_passthrough is False

    def test_nonzero_transition_tracks_pending(self, session):
        session.handle_prepare_transition(1, 42)
        assert session.get_pending_transition() == (42, 1)


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

    def test_downgrade_execute_enables_send_passthrough(self, session):
        session.handle_prepare_transition(0, 9)
        session.execute_transition(9)
        assert session._receive_passthrough is True
        assert session._send_passthrough is True

    def test_reupgrade_execute_disables_passthrough(self, session):
        session.handle_prepare_transition(0, 10)
        session.execute_transition(10)
        assert session._receive_passthrough is True
        assert session._send_passthrough is True

        session.handle_prepare_transition(1, 11)
        session.execute_transition(11)
        assert session._receive_passthrough is False
        assert session._send_passthrough is False

    def test_execute_clears_pending_only_for_matching_transition(self, session):
        session.handle_prepare_transition(1, 100)
        assert session.get_pending_transition() == (100, 1)

        session.execute_transition(99)
        assert session.get_pending_transition() == (100, 1)

        session.execute_transition(100)
        assert session.get_pending_transition() is None


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

    def test_returns_none_even_with_group(self, session):
        session.prepare_epoch(1)
        pkg = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xBB" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.handle_external_sender_package(pkg)
        assert session.leave_group() is None


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

    def test_requires_external_sender_package(self, session):
        session.prepare_epoch(1)
        with pytest.raises(ValueError, match="external sender package"):
            session.handle_welcome(1, b"\x00")


class TestHandleProposalsValidation:
    def test_rejects_add_when_user_not_expected(self, session, monkeypatch):
        session._group = object()
        session._external_sender = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        # CLIENT_CONNECT lists other members; 999 is not among them.
        session.add_expected_members([111])

        class _FakeMLSPlaintext:
            @staticmethod
            def deserialize(_blob):
                sender = SimpleNamespace(sender_type=2)  # EXTERNAL
                content = b"fake-proposal"
                framed = SimpleNamespace(sender=sender, content=content)
                tbs = SimpleNamespace(framed_content=framed)
                auth_content = SimpleNamespace(tbs=tbs)
                return SimpleNamespace(auth_content=auth_content)

        class _FakeProposalType:
            ADD = "add"
            REMOVE = "remove"

        class _FakeAddProposal:
            def __init__(self):
                self.proposal_type = _FakeProposalType.ADD
                self.key_package = b"kp"

        class _FakeProposal:
            @staticmethod
            def deserialize(_content):
                return _FakeAddProposal()

        def _fake_parse_proposals(_payload):
            return SimpleNamespace(operation_type=0, proposal_messages=[b"blob"])

        def _fake_kp_deserialize(_kp):
            identity = (999).to_bytes(8, "big")
            cred = SimpleNamespace(identity=identity)
            leaf = SimpleNamespace(credential=cred)
            return SimpleNamespace(leaf_node=leaf)

        called = {"process": 0, "commit": 0}

        monkeypatch.setattr("sorrydave.session.validate_group_external_sender", lambda *_, **__: None)
        monkeypatch.setattr("sorrydave.mls.opcodes.parse_proposals", _fake_parse_proposals)
        monkeypatch.setattr("rfc9420.messages.messages.MLSPlaintext", _FakeMLSPlaintext)
        monkeypatch.setattr("rfc9420.messages.data_structures.ProposalType", _FakeProposalType)
        monkeypatch.setattr("rfc9420.messages.data_structures.AddProposal", _FakeAddProposal)
        monkeypatch.setattr("rfc9420.messages.data_structures.Proposal", _FakeProposal)
        monkeypatch.setattr("rfc9420.messages.key_packages.KeyPackage.deserialize", _fake_kp_deserialize)
        monkeypatch.setattr("rfc9420.interop.wire.encode_handshake", lambda _msg: b"handshake")
        monkeypatch.setattr(
            "sorrydave.session.process_proposal",
            lambda *_, **__: called.__setitem__("process", called["process"] + 1),
        )
        monkeypatch.setattr(
            "sorrydave.mls.group_state.create_commit_and_welcome",
            lambda *_, **__: called.__setitem__("commit", called["commit"] + 1) or (b"c", []),
        )

        result = session.handle_proposals(b"ignored")
        assert called["process"] == 0
        assert called["commit"] == 0
        assert result is None

    def test_accepts_add_when_user_expected(self, session, monkeypatch):
        session._group = object()
        session._external_sender = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        session.add_expected_members([999])

        class _FakeMLSPlaintext:
            @staticmethod
            def deserialize(_blob):
                sender = SimpleNamespace(sender_type=2)  # EXTERNAL
                content = b"fake-proposal"
                framed = SimpleNamespace(sender=sender, content=content)
                tbs = SimpleNamespace(framed_content=framed)
                auth_content = SimpleNamespace(tbs=tbs)
                return SimpleNamespace(auth_content=auth_content)

        class _FakeProposalType:
            ADD = "add"
            REMOVE = "remove"

        class _FakeAddProposal:
            def __init__(self):
                self.proposal_type = _FakeProposalType.ADD
                self.key_package = b"kp"

        class _FakeProposal:
            @staticmethod
            def deserialize(_content):
                return _FakeAddProposal()

        def _fake_parse_proposals(_payload):
            return SimpleNamespace(operation_type=0, proposal_messages=[b"blob"])

        def _fake_kp_deserialize(_kp):
            identity = (999).to_bytes(8, "big")
            cred = SimpleNamespace(identity=identity)
            leaf = SimpleNamespace(credential=cred)
            return SimpleNamespace(leaf_node=leaf)

        called = {"process": 0}

        monkeypatch.setattr("sorrydave.session.validate_group_external_sender", lambda *_, **__: None)
        monkeypatch.setattr("sorrydave.mls.opcodes.parse_proposals", _fake_parse_proposals)
        monkeypatch.setattr("rfc9420.messages.messages.MLSPlaintext", _FakeMLSPlaintext)
        monkeypatch.setattr("rfc9420.messages.data_structures.ProposalType", _FakeProposalType)
        monkeypatch.setattr("rfc9420.messages.data_structures.AddProposal", _FakeAddProposal)
        monkeypatch.setattr("rfc9420.messages.data_structures.Proposal", _FakeProposal)
        monkeypatch.setattr("rfc9420.messages.key_packages.KeyPackage.deserialize", _fake_kp_deserialize)
        monkeypatch.setattr("rfc9420.interop.wire.encode_handshake", lambda _msg: b"handshake")
        monkeypatch.setattr(
            "sorrydave.session.process_proposal",
            lambda *_, **__: called.__setitem__("process", called["process"] + 1),
        )

        session.handle_proposals(b"ignored")
        assert called["process"] == 1

    def test_skips_add_for_local_user(self, session, monkeypatch):
        session._group = object()
        session._external_sender = ExternalSenderPackage(
            sequence_number=0,
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )

        class _FakeMLSPlaintext:
            @staticmethod
            def deserialize(_blob):
                sender = SimpleNamespace(sender_type=2)
                content = b"fake-proposal"
                framed = SimpleNamespace(sender=sender, content=content)
                tbs = SimpleNamespace(framed_content=framed)
                auth_content = SimpleNamespace(tbs=tbs)
                return SimpleNamespace(auth_content=auth_content)

        class _FakeProposalType:
            ADD = "add"
            REMOVE = "remove"

        class _FakeAddProposal:
            def __init__(self):
                self.proposal_type = _FakeProposalType.ADD
                self.key_package = b"kp"

        class _FakeProposal:
            @staticmethod
            def deserialize(_content):
                return _FakeAddProposal()

        def _fake_parse_proposals(_payload):
            return SimpleNamespace(operation_type=0, proposal_messages=[b"blob"])

        def _fake_kp_deserialize(_kp):
            identity = session._local_user_id.to_bytes(8, "big")
            cred = SimpleNamespace(identity=identity)
            leaf = SimpleNamespace(credential=cred)
            return SimpleNamespace(leaf_node=leaf)

        called = {"process": 0}

        monkeypatch.setattr("sorrydave.mls.opcodes.parse_proposals", _fake_parse_proposals)
        monkeypatch.setattr("rfc9420.messages.messages.MLSPlaintext", _FakeMLSPlaintext)
        monkeypatch.setattr("rfc9420.messages.data_structures.ProposalType", _FakeProposalType)
        monkeypatch.setattr("rfc9420.messages.data_structures.AddProposal", _FakeAddProposal)
        monkeypatch.setattr("rfc9420.messages.data_structures.Proposal", _FakeProposal)
        monkeypatch.setattr("rfc9420.messages.key_packages.KeyPackage.deserialize", _fake_kp_deserialize)
        monkeypatch.setattr("rfc9420.interop.wire.encode_handshake", lambda _msg: b"handshake")
        monkeypatch.setattr(
            "sorrydave.session.process_proposal",
            lambda *_, **__: called.__setitem__("process", called["process"] + 1),
        )

        result = session.handle_proposals(b"ignored")
        assert called["process"] == 0
        assert result is None

    def test_remove_expected_member_keeps_local_user(self, session):
        session.remove_expected_member(session._local_user_id)
        assert session._local_user_id in session._expected_member_ids


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
        session._current_epoch = 1
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


def _establish_uncommitted_group(session: DaveSession) -> None:
    session.prepare_epoch(1)
    pkg = ExternalSenderPackage(
        sequence_number=0,
        signature_key=b"\xAA" * 32,
        credential_type=1,
        identity=b"\x00" * 8,
    )
    session.handle_external_sender_package(pkg)
    session._refresh_send_ratchet()


class TestMediaReadyAndCryptorCache:
    def test_not_ready_before_epoch_is_established(self, session):
        _establish_uncommitted_group(session)
        assert session._group is not None
        assert session._send_ratchet is not None
        assert session._current_epoch == 0
        assert session.is_media_ready is False

    def test_ready_once_epoch_and_send_ratchet_exist(self, session):
        _establish_uncommitted_group(session)
        session._current_epoch = 1
        assert session.is_media_ready is True

    def test_get_encryptor_returns_cached_instance(self, session):
        _establish_uncommitted_group(session)
        session._current_epoch = 1
        first = session.get_encryptor()
        second = session.get_encryptor()
        assert first is second

    def test_get_decryptor_returns_cached_instance_for_sender(self, session):
        _establish_uncommitted_group(session)
        session._current_epoch = 1
        session._receive_ratchets[999] = session._send_ratchet
        first = session.get_decryptor(999)
        second = session.get_decryptor(999)
        assert first is second

    def test_sequential_encrypt_uses_increasing_nonces(self, session):
        _establish_uncommitted_group(session)
        session._current_epoch = 1
        encryptor = session.get_encryptor()
        encryptor.encrypt(b"\x11" * 8, "OPUS")
        encryptor.encrypt(b"\x22" * 8, "OPUS")
        assert encryptor._nonce == 2
        assert session.get_encryptor() is encryptor
        assert encryptor._nonce == 2

    def test_prepare_epoch_invalidates_cached_cryptors(self, session):
        _establish_uncommitted_group(session)
        session._current_epoch = 1
        session.get_encryptor()
        assert session._encryptor is not None
        session.prepare_epoch(1)
        assert session._encryptor is None
        assert session._decryptors == {}
        assert session.is_media_ready is False
