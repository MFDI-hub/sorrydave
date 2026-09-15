"""
Transport-free Voice Gateway helpers for :class:`~sorrydave.session.DaveSession`.

These functions compose opcode parsers with existing session methods. They do
not send WebSocket frames, coalesce proposals, execute opcode 22 while handling
opcode 29/30, or auto-build opcode 23. Callers own I/O, timing, and activation.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Union

from sorrydave.mls.opcodes import (
    ExternalSenderPackage,
    JsonPayload,
    build_invalid_commit_welcome_dict,
    parse_announce_commit,
    parse_client_disconnect,
    parse_clients_connect,
    parse_execute_transition,
    parse_external_sender_package,
    parse_prepare_transition,
    parse_proposals,
    parse_welcome_message,
)
from sorrydave.session import DaveSession, PrepareTransitionAction

__all__ = [
    "HandshakeApplyResult",
    "InvalidCommitRecovery",
    "PrepareTransitionResult",
    "ProposalApplyResult",
    "apply_proposals_message",
    "configure_occupied_join",
    "handle_announce_commit_wire",
    "handle_execute_transition_message",
    "handle_external_sender_wire",
    "handle_prepare_transition_message",
    "handle_welcome_wire",
    "recover_invalid_commit",
    "sync_client_disconnect",
    "sync_clients_connect",
]


@dataclass(frozen=True)
class ProposalApplyResult:
    """Cached opcode 27 result. Does not build or send opcode 28."""

    applied: int
    revoked: int
    skipped_self: int
    sequence_number: Union[int, None] = None
    operation_type: Union[int, None] = None

    @property
    def should_commit(self) -> bool:
        """True when cached proposals should later become opcode 28."""
        return self.applied > 0 or self.revoked > 0


@dataclass(frozen=True)
class HandshakeApplyResult:
    """Result of applying a full-wire opcode 29 or 30 payload.

    ``applied`` is True only when the local MLS epoch advanced. This helper
    never calls :meth:`DaveSession.execute_transition` and never builds opcode 23.
    """

    transition_id: int
    applied: bool
    media_ready: bool


@dataclass(frozen=True)
class PrepareTransitionResult:
    """Parsed opcode 21 after it has been applied to the session."""

    protocol_version: int
    transition_id: int
    action: PrepareTransitionAction
    media_ready: bool


@dataclass(frozen=True)
class InvalidCommitRecovery:
    """Outbound opcode 31 JSON and opcode 26 key package. Caller sends both."""

    transition_id: int
    op31: dict[str, Any]
    key_package: bytes


def sync_clients_connect(session: DaveSession, payload: JsonPayload) -> list[int]:
    """Parse opcode 11 and register expected members on ``session``."""
    user_ids = parse_clients_connect(payload)
    session.add_expected_members(user_ids)
    return user_ids


def sync_client_disconnect(session: DaveSession, payload: JsonPayload) -> int:
    """Parse opcode 13 and drop that user from expected members."""
    user_id = parse_client_disconnect(payload)
    session.remove_expected_member(user_id)
    return user_id


def configure_occupied_join(
    session: DaveSession,
    other_user_ids: Union[Iterable[int | str], None] = None,
) -> bool:
    """Wait for opcode 30 when other members are already in the channel."""
    return session.configure_occupied_join(other_user_ids)


def handle_prepare_transition_message(
    session: DaveSession, payload: JsonPayload
) -> PrepareTransitionResult:
    """Parse opcode 21 and apply it. Does not send opcode 23."""
    protocol_version, transition_id = parse_prepare_transition(payload)
    action = session.handle_prepare_transition(protocol_version, transition_id)
    return PrepareTransitionResult(
        protocol_version=protocol_version,
        transition_id=transition_id,
        action=action,
        media_ready=session.is_media_ready,
    )


def handle_execute_transition_message(session: DaveSession, payload: JsonPayload) -> int:
    """Parse opcode 22 and execute that transition. Returns the transition id."""
    transition_id = parse_execute_transition(payload)
    session.execute_transition(transition_id)
    return transition_id


def handle_external_sender_wire(session: DaveSession, data: bytes) -> ExternalSenderPackage:
    """Parse and apply a full-wire opcode 25 payload."""
    pkg = parse_external_sender_package(data)
    session.handle_external_sender_package(data)
    return pkg


def apply_proposals_message(session: DaveSession, data: bytes) -> ProposalApplyResult:
    """Parse opcode 27 metadata and cache proposals. Does not send opcode 28."""
    parsed = parse_proposals(data)
    summary = session.apply_proposals(data)
    return ProposalApplyResult(
        applied=int(summary.get("applied", 0)),
        revoked=int(summary.get("revoked", 0)),
        skipped_self=int(summary.get("skipped_self", 0)),
        sequence_number=parsed.sequence_number,
        operation_type=parsed.operation_type,
    )


def handle_announce_commit_wire(session: DaveSession, data: bytes) -> HandshakeApplyResult:
    """Parse and apply a full-wire opcode 29 payload. Does not execute the transition."""
    transition_id, commit_bytes = parse_announce_commit(data)
    epoch_before = session.current_epoch
    session.handle_commit(transition_id, commit_bytes)
    return HandshakeApplyResult(
        transition_id=transition_id,
        applied=session.current_epoch > epoch_before,
        media_ready=session.is_media_ready,
    )


def handle_welcome_wire(session: DaveSession, data: bytes) -> HandshakeApplyResult:
    """Parse and apply a full-wire opcode 30 payload. Does not execute the transition."""
    transition_id, welcome_bytes = parse_welcome_message(data)
    epoch_before = session.current_epoch
    session.handle_welcome(transition_id, welcome_bytes)
    return HandshakeApplyResult(
        transition_id=transition_id,
        applied=session.current_epoch > epoch_before,
        media_ready=session.is_media_ready,
    )


def recover_invalid_commit(session: DaveSession, transition_id: int) -> InvalidCommitRecovery:
    """Reset MLS state and return opcode 31 JSON plus a fresh opcode 26 payload."""
    tid = int(transition_id)
    _op31_bytes, key_package = session.recover_from_invalid_commit(tid)
    return InvalidCommitRecovery(
        transition_id=tid,
        op31=build_invalid_commit_welcome_dict(tid),
        key_package=key_package,
    )
