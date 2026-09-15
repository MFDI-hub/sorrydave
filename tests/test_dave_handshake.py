"""Transition-state regressions for zero/nonzero DAVE handshake activation."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from types import MethodType, SimpleNamespace

from sorrydave.mls.opcodes import ExternalSenderPackage
from sorrydave.session import DaveSession

from tests._voice_imports import load_voice_module


class _KeepAlive:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)


def _esp() -> ExternalSenderPackage:
    return ExternalSenderPackage(
        sequence_number=0,
        signature_key=b"\xAA" * 32,
        credential_type=1,
        identity=b"\x00" * 8,
    )


def _group_session(user_id: int = 111) -> DaveSession:
    session = DaveSession(local_user_id=user_id, protocol_version=1, channel_id=123)
    session.prepare_epoch(1)
    session.handle_external_sender_package(_esp())
    session._refresh_send_ratchet()
    return session


class TestSessionTransitionReadiness:
    def test_op29_tid0_own_commit_is_media_ready_without_execute_transition(self):
        session = _group_session()
        assert session.is_media_ready is False
        session._current_epoch = 1
        assert session.is_media_ready is True
        session.execute_transition(0)
        assert session.is_media_ready is True

    def test_op21_tid0_executes_immediately(self):
        session = _group_session()
        session._current_epoch = 1
        session.handle_prepare_transition(1, 0)
        assert session.get_pending_transition() is None

    def test_op21_nonzero_records_pending_and_does_not_require_immediate_activation(self):
        session = _group_session()
        session._current_epoch = 1
        session.handle_prepare_transition(1, 7)
        pending = session.get_pending_transition()
        assert pending == (7, 1)
        session.execute_transition(7)
        assert session.get_pending_transition() is None

    def test_op21_version0_enables_receive_passthrough(self):
        session = _group_session()
        session._current_epoch = 1
        session.handle_prepare_transition(0, 9)
        assert session._receive_passthrough is True


class TestMlsManagerPendingTransitions:
    def setup_method(self):
        mls_mod = load_voice_module("MlsManager")
        self.MLSManager = mls_mod.MLSManager
        self._voice = _KeepAlive(
            media_client=_KeepAlive(kind="voice", channel_id=123456, _server_id=None)
        )
        self._media = _KeepAlive()
        self.mgr = self.MLSManager(self._voice, self._media, 42)

    def test_record_pending_ignores_transition_id_zero(self):
        self.mgr.record_pending_transition(0, 1)
        assert self.mgr._pending_transitions == {}

    def test_record_and_pop_nonzero_pending_transition(self):
        self.mgr.record_pending_transition(7, 1)
        assert self.mgr.pop_pending_protocol_version(7) == 1
        assert self.mgr.pop_pending_protocol_version(7) is None

    def test_is_media_ready_requires_session_epoch(self):
        assert self.mgr.is_media_ready() is False
        session = _group_session(42)
        self.mgr._session = session
        assert self.mgr.is_media_ready() is False
        session._current_epoch = 1
        assert self.mgr.is_media_ready() is True
        assert self.mgr.has_established_group() is True

    def test_start_protocol_clears_pending_transitions(self):
        self.mgr.record_pending_transition(4, 1)

        async def _run():
            await self.mgr.start_protocol(1)

        asyncio.run(_run())
        assert self.mgr._pending_transitions == {}
        assert self.mgr._session is not None
        assert self.mgr.is_media_ready() is False


class _HandshakeHarness:
    """Minimal MediaConnection stand-in that binds the real transition methods."""

    def __init__(self, mls_manager, *, media_ready=False, encrypt_ok=True):
        conn_mod = load_voice_module("media_connection")
        MediaConnection = conn_mod.MediaConnection
        self.mls_manager = mls_manager
        self.logger = logging.getLogger("test-dave-handshake")
        self.alive = True
        self._dave_strict_mode = True
        self._dave_handshake_watchdog_task = None
        self._dave_transition_opcodes_received = set()
        self.dave_ready_ids: list[int] = []
        self.fail_reasons: list[str] = []
        self.set_dave_active_calls = 0
        self.encrypt_ok = encrypt_ok
        self.bot = SimpleNamespace(
            settings=SimpleNamespace(
                voice=SimpleNamespace(dave=SimpleNamespace(strict_handshake_timeout=0.05))
            )
        )
        self.media_client = SimpleNamespace(
            media_session=SimpleNamespace(
                set_dave_active=self._set_dave_session_active,
                _speaking_flags=0,
            ),
            handle_dave_failure=self._handle_dave_failure,
        )
        if media_ready:
            session = _group_session(int(mls_manager.user_id))
            session._current_epoch = 1
            mls_manager._session = session
        for name in (
            "_activate_dave_if_session_ready",
            "_after_mls_handshake_message",
            "_maybe_send_ready_for_transition",
            "_run_dave_handshake_watchdog",
            "_cancel_dave_handshake_watchdog",
            "_is_dave_active",
            "_set_dave_active",
            "_is_dave_strict",
            "_was_ready_sent_for",
            "_mark_ready_sent_for",
            "_get_dave_protocol_version",
            "_get_dave_transition_id",
            "_set_dave_transition_id",
            "_get_dave_received_opcodes_for_diagnostics",
            "_debug_dave_state",
        ):
            setattr(self, name, MethodType(getattr(MediaConnection, name), self))

    def _set_dave_session_active(self):
        if not self.encrypt_ok:
            raise RuntimeError("no usable encryptor")
        self.set_dave_active_calls += 1

    async def dave_ready(self, transition_id: int):
        self.dave_ready_ids.append(int(transition_id))
        self._mark_ready_sent_for(int(transition_id))

    async def _fail_dave_join(self, reason: str) -> None:
        self.fail_reasons.append(reason)
        self._set_dave_active(False)

    async def _handle_dave_failure(self, reason: str) -> None:
        self.fail_reasons.append(reason)

    async def _replay_sink_wants(self) -> None:
        return None

    async def close(self) -> None:
        return None


def _make_mgr():
    mls_mod = load_voice_module("MlsManager")
    voice = _KeepAlive(
        media_client=_KeepAlive(kind="voice", channel_id=123456, _server_id=None)
    )
    media = _KeepAlive()
    return mls_mod.MLSManager(voice, media, 99), voice, media


class TestMediaConnectionTransitionDispatch:
    def test_op29_tid0_activates_immediately_and_reports_ready(self):
        mgr, _voice, _media = _make_mgr()
        harness = _HandshakeHarness(mgr, media_ready=True)

        async def _run():
            await harness._after_mls_handshake_message(0)

        asyncio.run(_run())
        assert harness.dave_ready_ids == [0]
        assert harness.set_dave_active_calls == 1
        assert harness.mls_manager.active is True
        assert harness._dave_handshake_watchdog_task is None

    def test_op29_nonzero_sends_op23_and_stays_inactive_until_op22(self):
        mgr, _voice, _media = _make_mgr()
        mgr.protocol_version = 1
        harness = _HandshakeHarness(mgr, media_ready=True)

        async def _run():
            await harness._after_mls_handshake_message(7)
            assert harness.dave_ready_ids == [7]
            assert harness.mls_manager.active is False
            assert harness.mls_manager._pending_transitions[7] == 1
            harness.mls_manager.pop_pending_protocol_version(7)
            harness._set_dave_active(True)
            harness.media_client.media_session.set_dave_active()

        asyncio.run(_run())
        assert harness.set_dave_active_calls == 1
        assert harness.mls_manager.active is True

    def test_activation_failure_is_reported_when_encryptor_missing(self):
        mgr, _voice, _media = _make_mgr()
        harness = _HandshakeHarness(mgr, media_ready=True, encrypt_ok=False)

        async def _run():
            await harness._activate_dave_if_session_ready(source="op29/30 tid=0")

        asyncio.run(_run())
        assert harness.fail_reasons
        assert harness.mls_manager.active is False

    def test_watchdog_cancels_after_tid0_activation(self):
        mgr, _voice, _media = _make_mgr()
        harness = _HandshakeHarness(mgr, media_ready=True)

        async def _run():
            async def _watchdog_placeholder():
                await asyncio.sleep(30)

            watchdog = asyncio.create_task(_watchdog_placeholder())
            harness._dave_handshake_watchdog_task = watchdog
            await harness._after_mls_handshake_message(0)
            assert harness._dave_handshake_watchdog_task is None
            with contextlib.suppress(asyncio.CancelledError):
                await watchdog
            assert watchdog.cancelled()

        asyncio.run(_run())
        assert harness._dave_handshake_watchdog_task is None
        assert harness.mls_manager.active is True

    def test_watchdog_timeout_after_op29_reports_media_ready_not_missing_opcodes(self):
        mgr, _voice, _media = _make_mgr()
        harness = _HandshakeHarness(mgr, media_ready=False)
        harness._dave_transition_opcodes_received = {25, 27, 29}

        async def _run():
            await harness._run_dave_handshake_watchdog()

        asyncio.run(_run())
        assert harness.fail_reasons
        assert "media-ready" in harness.fail_reasons[0]
        assert "op22" not in harness.fail_reasons[0]

    def test_watchdog_skips_fail_when_already_active(self):
        mgr, _voice, _media = _make_mgr()
        harness = _HandshakeHarness(mgr, media_ready=True)
        harness.mls_manager.set_active(True)
        harness._dave_transition_opcodes_received = {29}

        async def _run():
            await harness._run_dave_handshake_watchdog()

        asyncio.run(_run())
        assert harness.fail_reasons == []
