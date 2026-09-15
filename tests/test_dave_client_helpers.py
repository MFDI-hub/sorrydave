"""New DAVE client-facing helpers on DaveSession and related APIs."""

from __future__ import annotations

import orjson
import pytest
from sorrydave import (
    PREPARE_DEFER_UNTIL_MEDIA_READY,
    PREPARE_WAIT_FOR_EXECUTE,
    SILENCE_PACKET,
    DaveSession,
    SharedIdentityContext,
    mls_channel_id_from_stream_server_id,
    mls_group_id_from_channel_id,
    mls_group_id_from_stream_server_id,
    protocol_frame_check,
)
from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.group_state import iter_member_keys
from sorrydave.mls.opcodes import ExternalSenderPackage, build_invalid_commit_welcome
from sorrydave.persistent_keys import generate_p256_keypair


def _esp() -> ExternalSenderPackage:
    return ExternalSenderPackage(
        sequence_number=0,
        signature_key=b"\xaa" * 32,
        credential_type=1,
        identity=b"\x00" * 8,
    )


def _ready_session(user_id: int = 111) -> DaveSession:
    session = DaveSession(local_user_id=user_id, channel_id=123)
    session.prepare_epoch(1)
    session.handle_external_sender_package(_esp())
    session._current_epoch = 1
    session._refresh_send_ratchet()
    return session


class TestStreamGroupId:
    def test_stream_server_id_minus_one(self):
        assert mls_channel_id_from_stream_server_id(100) == 99
        assert mls_group_id_from_stream_server_id(100) == mls_group_id_from_channel_id(99)


class TestSessionProperties:
    def test_epoch_and_version(self):
        session = DaveSession(local_user_id=1, protocol_version=1, channel_id=9)
        assert session.protocol_version == 1
        assert session.current_epoch == 0
        session.handle_prepare_transition(1, 4)
        assert session.protocol_version == 1

    def test_receive_ratchet_user_ids_public(self):
        session = _ready_session()
        assert session.receive_ratchet_user_ids == frozenset()
        session._receive_ratchets[999] = session._send_ratchet
        assert session.receive_ratchet_user_ids == frozenset({999})

    def test_encrypt_frame_appends_magic(self):
        session = _ready_session()
        frame = session.encrypt_frame(b"hello-opus", "OPUS")
        assert protocol_frame_check(frame)
        assert frame[-2:] == b"\xfa\xfa"


class TestIdentityFromGroup:
    def test_list_members_local_only(self):
        session = _ready_session(222)
        members = session.list_members()
        assert members == [222]
        assert session.member_user_ids == frozenset({222})
        key = session.get_local_signature_public_key()
        assert key[0] == 0x04
        assert len(key) == 65
        assert session.get_member_signature_key(222) == key

    def test_pairwise_fingerprint_requires_remote(self):
        session = _ready_session(222)
        with pytest.raises(ValueError, match="remote"):
            session.get_pairwise_fingerprint(222)
        with pytest.raises(KeyError):
            session.get_pairwise_fingerprint(999)

    def test_iter_member_keys_matches_session(self):
        session = _ready_session(333)
        keys = iter_member_keys(session._group)
        assert len(keys) == 1
        _leaf, identity, sig = keys[0]
        assert int.from_bytes(identity[:8], "big") == 333
        assert sig == session.get_local_signature_public_key()


class TestRecoverFromInvalidCommit:
    def test_returns_op31_and_op26(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        session.prepare_epoch(1)
        op31, op26 = session.recover_from_invalid_commit(12)
        assert orjson.loads(op31) == orjson.loads(build_invalid_commit_welcome(12))
        assert op26[0] == 26
        assert session.current_epoch == 0

    def test_handle_welcome_invalid_raises_invalid_commit(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        session.prepare_epoch(1)
        session.handle_external_sender_package(_esp())
        with pytest.raises(InvalidCommitError):
            session.handle_welcome(1, b"\x00")


class TestPrepareTransitionAction:
    def test_defer_when_not_ready(self):
        session = DaveSession(local_user_id=1)
        assert session.handle_prepare_transition(1, 0) == PREPARE_DEFER_UNTIL_MEDIA_READY
        assert session.handle_prepare_transition(1, 8) == PREPARE_WAIT_FOR_EXECUTE


class TestOccupiedJoin:
    def test_configures_wait_for_welcome_when_others_present(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        session.prepare_epoch(1)
        session.handle_external_sender_package(_esp())
        assert session.configure_occupied_join([8, 9]) is True
        assert session.take_commit_welcome() is None

    def test_solo_join_does_not_wait(self):
        session = DaveSession(local_user_id=7, channel_id=1)
        assert session.configure_occupied_join([]) is False


class TestPersistentSharedIdentity:
    def test_from_persistent_key_reuses_signature(self):
        pub, priv = generate_p256_keypair()
        ctx = SharedIdentityContext.from_persistent_key(55, priv)
        _kp, hpke, signing, enc = ctx.get_supplier()()
        assert signing == priv
        session = DaveSession(local_user_id=55, identity_supplier=ctx.get_supplier(), channel_id=1)
        session.prepare_epoch(1)
        session.handle_external_sender_package(_esp())
        session._current_epoch = 1
        session._refresh_send_ratchet()
        assert session.get_local_signature_public_key() == pub
        assert hpke and enc


class TestPublicMediaExports:
    def test_silence_packet_and_frame_check(self):
        assert bytes((0xF8, 0xFF, 0xFE)) == SILENCE_PACKET
        assert protocol_frame_check(SILENCE_PACKET) is False
        assert protocol_frame_check(b"\x00" * 20) is False
