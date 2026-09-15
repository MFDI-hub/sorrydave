"""
DaveSession: high-level facade for DAVE media session.
Maps Voice Gateway opcodes to MLS and media transform; no I/O.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Callable, Literal, Union

from sorrydave.crypto.ratchet import KeyRatchet
from sorrydave.exceptions import InvalidCommitError
from sorrydave.media.transform import FrameDecryptor, FrameEncryptor
from sorrydave.mls.group_state import (
    apply_staged_commit,
    create_group,
    get_dave_crypto_provider,
    iter_members,
    process_proposal,
    stage_commit_and_welcome,
    validate_group_dave_ciphersuite_and_extensions,
    validate_group_external_sender,
)
from sorrydave.mls.opcodes import ExternalSenderPackage, parse_external_sender_package

if TYPE_CHECKING:
    from rfc9420 import DefaultCryptoProvider
    from rfc9420.api.session import MLSGroupSession

# Placeholder only for local tests that never talk to Discord. The voice
# gateway drops commits whose MLS group ID is not the channel snowflake.
_DEFAULT_GROUP_ID = b"dave-default-group"

PREPARE_EXECUTE_NOW = "execute_now"
PREPARE_DEFER_UNTIL_MEDIA_READY = "defer_until_media_ready"
PREPARE_WAIT_FOR_EXECUTE = "wait_for_opcode_22"
PrepareTransitionAction = Literal[
    "execute_now",
    "defer_until_media_ready",
    "wait_for_opcode_22",
]


def mls_group_id_from_channel_id(channel_id: int | str) -> bytes:
    """
    Encode a Discord channel (or stream) snowflake as an MLS group ID.

    Working DAVE stacks (davey, discord-native-voice, libdave) use
    ``channel_id`` as eight big-endian bytes. The voice gateway keeps this
    group ID with epoch and ciphersuite and will not broadcast a commit
    whose group context does not match.

    Args:
        channel_id (int | str): Voice channel ID, or the media-session ID
            used for a Go Live stream.

    Returns:
        bytes: 8-byte big-endian MLS group ID.
    """
    return int(channel_id).to_bytes(8, "big")


def mls_channel_id_from_stream_server_id(rtc_server_id: int | str) -> int:
    """
    Discord Go Live MLS group ID snowflake: ``rtc_server_id - 1``.

    Pass the result as ``DaveSession(..., channel_id=...)``.
    """
    return int(rtc_server_id) - 1


def mls_group_id_from_stream_server_id(rtc_server_id: int | str) -> bytes:
    """Encode a Go Live ``rtc_server_id`` as the 8-byte MLS group ID."""
    return mls_group_id_from_channel_id(mls_channel_id_from_stream_server_id(rtc_server_id))


class DaveSession:
    """
    High-level facade for managing a DAVE media session.

    Holds MLS group state, per-sender ratchets, and provides frame encrypt/decrypt.
    Performs no I/O; you pass in bytes (opcode payloads, encoded frames) and get back bytes.

    Typical usage:
        1. Create: DaveSession(local_user_id=..., channel_id=...).
        2. Prepare epoch 1: prepare_epoch(1) -> send returned bytes as opcode 26.
        3. Handle opcode 25: handle_external_sender_package(package_bytes).
        4. Handle opcode 27: handle_proposals(proposal_bytes) -> send return value as opcode 28 if not None.
        5. Handle opcode 29: parse_announce_commit then handle_commit(transition_id, commit_bytes).
        6. Handle opcode 30 (if you were added): parse_welcome_message then handle_welcome(transition_id, welcome_bytes).
        7. Handle opcode 22: parse_execute_transition then execute_transition(transition_id).
        8. Media: get_encryptor().encrypt(frame, codec=...) and get_decryptor(sender_id).decrypt(protocol_frame).
    """

    def __init__(
        self,
        local_user_id: int,
        protocol_version: int = 1,
        identity_supplier: Union[Callable[[], tuple[bytes, bytes, bytes, bytes]], None] = None,
        *,
        channel_id: Union[int, str, None] = None,
        group_id: Union[bytes, None] = None,
    ):
        """
        Initialize a DAVE session for the local user.

        Args:
            local_user_id (int): Local user identifier (e.g. Discord snowflake).
            protocol_version (int): DAVE protocol version. Defaults to 1.
            identity_supplier (Union[Callable[[], tuple[bytes, bytes, bytes, bytes]], None]): Optional
                callable that returns (key_package_bytes, init_private_key, signing_key_der,
                encryption_private_key) to use the same identity across multiple sessions
                (e.g. voice channel + Go Live). When set, prepare_epoch(1) uses it instead of
                generating a new key package. Use SharedIdentityContext to share one keypair
                across sessions. A 3-tuple without encryption_private_key is also accepted.
            channel_id (Union[int, str, None]): Voice channel (or stream) snowflake. Required
                for a commit the Discord voice gateway will broadcast. Encoded as eight
                big-endian bytes for the MLS group ID, matching davey/libdave.
            group_id (Union[bytes, None]): Explicit MLS group ID. Overrides channel_id when set.
        """
        self._local_user_id = local_user_id
        self._protocol_version = protocol_version
        self._group: Union[MLSGroupSession, None] = None
        self._crypto: Union[DefaultCryptoProvider, None] = None
        self._hpke_private_key: Union[bytes, None] = None
        self._encryption_private_key: Union[bytes, None] = None
        self._signing_key_der: Union[bytes, None] = None
        self._external_sender: Union[ExternalSenderPackage, None] = None
        # Per-sender KeyRatchet for current epoch (sender_user_id -> KeyRatchet)
        self._send_ratchet: Union[KeyRatchet, None] = None
        self._receive_ratchets: dict[int, KeyRatchet] = {}
        # Retained previous-epoch receive ratchets (expiry_monotonic, ratchet_dict) for in-flight decryption
        self._retained_receive_ratchets: list[tuple[float, dict[int, KeyRatchet]]] = []
        self._retention_seconds = 10.0
        # Passthrough mode for upgrade/downgrade (receive enabled first on downgrade, then send on execute)
        self._receive_passthrough = False
        self._send_passthrough = False
        # Epoch/transition state
        self._current_epoch = 0
        self._member_leaf_indices: dict[int, int] = {}
        # Pending protocol transition (non-zero transition_id); cleared on execute
        self._pending_transition_id: Union[int, None] = None
        self._pending_transition_protocol_version: Union[int, None] = None
        self._key_package_bytes: Union[bytes, None] = None
        self._channel_id: Union[int, None] = int(channel_id) if channel_id is not None else None
        if group_id is not None:
            self._group_id = bytes(group_id)
            if self._channel_id is None and len(self._group_id) == 8:
                self._channel_id = int.from_bytes(self._group_id, "big")
        elif self._channel_id is not None:
            self._group_id = mls_group_id_from_channel_id(self._channel_id)
        else:
            self._group_id = _DEFAULT_GROUP_ID
        # Optional shared identity: same keypair across concurrent voice gateway connections
        self._identity_supplier: Union[Callable[[], tuple[bytes, bytes, bytes, bytes]], None] = (
            identity_supplier
        )
        # Expected media session members (from opcodes 11/13); add proposals are validated against this.
        # The local user is always expected: CLIENT_CONNECT lists other users, but the gateway
        # may still broadcast an Add for us. Skipping that Add produces a commit that omits a
        # proposal reference, which the gateway silently drops.
        self._expected_member_ids: set[int] = {int(local_user_id)}
        # True when Opcode 11 listed other users before this session existed.
        # Those members commit Add(us); we wait for op30 instead of racing a
        # local-group commit the gateway or official client will reject.
        self._wait_for_welcome: bool = False
        # Client commit validity: when epoch is 0, only accept commit that matches our initial local group commit
        self._initial_commit_bytes: Union[bytes, None] = None
        # Candidate commits remain staged until the gateway selects one via op29.
        # Multiple op27 messages can produce multiple candidates for one epoch.
        self._outbound_staged_commits: dict[bytes, object] = {}
        # Cached frame cryptors: rebuilt only when ratchets, passthrough, or group change.
        self._encryptor: Union[FrameEncryptor, None] = None
        self._decryptors: dict[int, FrameDecryptor] = {}

    @property
    def channel_id(self) -> Union[int, None]:
        """Voice channel (or stream) snowflake used as the MLS group ID, if known."""
        return self._channel_id

    @property
    def group_id(self) -> bytes:
        """MLS group ID bytes. Discord requires the channel snowflake as 8 big-endian bytes."""
        return self._group_id

    @group_id.setter
    def group_id(self, value: Union[bytes, int, str]) -> None:
        """
        Set the MLS group ID before the local group is created.

        Accepts raw bytes or a Discord snowflake (int/str). Snowflake values are
        encoded as eight big-endian bytes. Must be set before
        ``handle_external_sender_package`` / ``prepare_epoch(1)`` create the group.
        """
        if isinstance(value, bytes):
            self._group_id = value
            if len(value) == 8:
                self._channel_id = int.from_bytes(value, "big")
            return
        self._channel_id = int(value)
        self._group_id = mls_group_id_from_channel_id(self._channel_id)

    @property
    def protocol_version(self) -> int:
        """DAVE protocol version this session was created with or last prepared for."""
        return self._protocol_version

    @property
    def current_epoch(self) -> int:
        """Local MLS epoch. 0 means the group is not yet established."""
        return self._current_epoch

    @property
    def member_user_ids(self) -> frozenset[int]:
        """Snowflake user IDs of occupied MLS leaves, if a group exists."""
        return frozenset(self.list_members())

    @property
    def is_media_ready(self) -> bool:
        """True when the MLS group is established enough to encrypt (davey.ready equivalent)."""
        if self._group is None or self._current_epoch <= 0:
            return False
        try:
            if self._send_ratchet is None:
                self._refresh_send_ratchet()
            return self._send_ratchet is not None
        except Exception:
            return False

    def _invalidate_cryptors(self) -> None:
        """Drop cached encryptor/decryptors so the next get_* rebuilds them."""
        self._encryptor = None
        self._decryptors = {}

    def handle_external_sender_package(self, pkg: Union[ExternalSenderPackage, bytes]) -> None:
        """
        Process opcode 25: store voice gateway external sender and optionally create group.

        When we already have a key package (e.g. after prepare_epoch(1)), creates a local
        group with the external sender. Call before create_group or before handle_welcome.

        Args:
            pkg (Union[ExternalSenderPackage, bytes]): Parsed package or raw opcode 25 payload.
        """
        if isinstance(pkg, bytes):
            pkg = parse_external_sender_package(pkg)
        self._external_sender = pkg
        if self._group is not None:
            return
        if self._key_package_bytes is None:
            return
        if self._crypto is None:
            self._crypto = get_dave_crypto_provider()
        self._group = create_group(
            self._group_id,
            self._key_package_bytes,
            self._crypto,
            external_sender_signature_key=pkg.signature_key,
            external_sender_credential_type=pkg.credential_type,
            external_sender_identity=pkg.identity,
        )

    def prepare_epoch(self, epoch_id: int) -> Union[bytes, None]:
        """
        Prepare for new epoch (e.g. after select_protocol_ack or prepare_epoch).

        Opcode 24 (dave_protocol_prepare_epoch) uses JSON field "epoch"; protocol.md
        sometimes refers to this as "epoch_id".

        Args:
            epoch_id (int): Epoch identifier. Only epoch_id == 1 triggers key package creation.

        Returns:
            Union[bytes, None]: Opcode 26 (key package) payload if epoch_id == 1, else None.
        """
        if epoch_id != 1:
            return None
        # Sole member reset: clear local group state per protocol (epoch=1 means new group)
        self._group = None
        self._send_ratchet = None
        self._receive_ratchets = {}
        self._retained_receive_ratchets = []
        self._invalidate_cryptors()
        self._current_epoch = 0
        self._outbound_staged_commits.clear()

        from sorrydave.mls.opcodes import build_key_package_message

        if self._identity_supplier is not None:
            material = self._identity_supplier()
            kp_bytes, hpke_private, signing_der = material[0], material[1], material[2]
            encryption_private = material[3] if len(material) > 3 else None
        else:
            from sorrydave.mls.group_state import create_key_package

            if self._crypto is None:
                self._crypto = get_dave_crypto_provider()
            kp_bytes, hpke_private, signing_der, encryption_private = create_key_package(
                self._local_user_id, self._crypto
            )
        self._hpke_private_key = hpke_private
        self._encryption_private_key = encryption_private
        self._signing_key_der = signing_der
        self._key_package_bytes = kp_bytes
        if self._external_sender is not None and self._group is None:
            self._group = create_group(
                self._group_id,
                self._key_package_bytes,
                self._crypto,
                external_sender_signature_key=self._external_sender.signature_key,
                external_sender_credential_type=self._external_sender.credential_type,
                external_sender_identity=self._external_sender.identity,
            )
        return build_key_package_message(kp_bytes)

    def set_wait_for_welcome(self, enabled: bool) -> None:
        """Wait for opcode 30 instead of committing a local group (occupied join)."""
        self._wait_for_welcome = bool(enabled)

    def add_expected_members(self, user_ids: Iterable[int | str]) -> None:
        """
        Add user IDs to the set of expected media session members.

        Call after receiving opcode 11 (clients_connect). The local user is always
        expected. Add proposals for other users not in this set are refused once
        any non-local member has been registered.
        """
        for uid in user_ids:
            self._expected_member_ids.add(int(uid))

    def remove_expected_member(self, user_id: int | str) -> None:
        """
        Remove a user ID from the set of expected media session members.

        Call after receiving opcode 13 (client_disconnect). That user will not be
        accepted in add proposals until they appear again in clients_connect.
        The local user cannot be removed.
        """
        uid = int(user_id)
        if uid == self._local_user_id:
            return
        self._expected_member_ids.discard(uid)

    def _is_expected_add_user(self, add_user_id: int) -> bool:
        """Return True if an Add proposal for this user should be processed."""
        if add_user_id == self._local_user_id:
            return True
        extra = self._expected_member_ids - {self._local_user_id}
        if not extra:
            # Opcode 11 has not registered other members yet; do not filter.
            return True
        return add_user_id in self._expected_member_ids

    def apply_proposals(self, proposal_bytes: bytes) -> dict[str, int]:
        """
        Cache opcode 27 proposals without creating a commit.

        Call :meth:`take_commit_welcome` after a short quiet period so Remove+Add
        batches in the same epoch become one op28. The gateway drops commits that
        omit any unrevoked proposal reference.

        Returns:
            dict[str, int]: ``applied``, ``revoked``, ``skipped_self``.
        """
        summary = {"applied": 0, "revoked": 0, "skipped_self": 0}
        if self._group is None:
            return summary
        from sorrydave.mls.opcodes import iter_proposal_plaintexts, parse_proposals

        try:
            proposals_msg = parse_proposals(proposal_bytes)
        except Exception:
            return summary

        if proposals_msg.operation_type == 1:
            if proposals_msg.proposal_refs:
                for ref in proposals_msg.proposal_refs:
                    with contextlib.suppress(Exception):
                        self._group.revoke_proposal(ref)
                        summary["revoked"] += 1
            self._outbound_staged_commits.clear()
            return summary
        if proposals_msg.operation_type != 0 or not proposals_msg.proposal_messages:
            return summary
        from rfc9420 import SenderType
        from rfc9420.interop.wire import encode_handshake
        from rfc9420.messages.data_structures import (
            AddProposal,
            Proposal,
            ProposalType,
        )
        from rfc9420.messages.key_packages import KeyPackage

        allowed_proposal_types = {ProposalType.ADD, ProposalType.REMOVE}
        vector_blob = proposals_msg.proposal_messages[0]
        mls_messages = iter_proposal_plaintexts(vector_blob)
        if not mls_messages:
            return summary

        incomplete = False
        for msg in mls_messages:
            try:
                if self._external_sender is None:
                    return summary
                sender = msg.auth_content.tbs.framed_content.sender
                if sender.sender_type != SenderType.EXTERNAL:
                    continue
                content_bytes = msg.auth_content.tbs.framed_content.content
                proposal = None
                with contextlib.suppress(Exception):
                    proposal = Proposal.deserialize(content_bytes)
                if proposal is None:
                    incomplete = True
                    continue
                proposal_type = proposal.proposal_type
                if proposal_type not in allowed_proposal_types:
                    continue
                if proposal_type == ProposalType.ADD:
                    if not isinstance(proposal, AddProposal):
                        incomplete = True
                        continue
                    kp = KeyPackage.deserialize(proposal.key_package)
                    identity = (
                        kp.leaf_node.credential.identity
                        if kp.leaf_node and kp.leaf_node.credential
                        else None
                    )
                    if not identity:
                        incomplete = True
                        continue
                    add_user_id = int.from_bytes(identity[:8], "big")
                    if add_user_id == self._local_user_id:
                        # Already the sole member of the local pending group.
                        # Cache nothing: applying Add(self) duplicates our leaf.
                        # Occupied joins must wait for Welcome instead of committing.
                        summary["skipped_self"] += 1
                        continue
                    if not self._is_expected_add_user(add_user_id):
                        return summary
                process_proposal(
                    self._group,
                    encode_handshake(msg),
                    sender_leaf_index=0,
                    sender_type=int(SenderType.EXTERNAL),
                )
                summary["applied"] += 1
            except Exception:
                incomplete = True
        if incomplete:
            return {"applied": 0, "revoked": summary["revoked"], "skipped_self": summary["skipped_self"]}
        return summary

    def take_commit_welcome(self) -> Union[bytes, None]:
        """Build one opcode 28 payload covering all currently cached proposals."""
        if self._group is None:
            return None
        if self._wait_for_welcome and self._current_epoch == 0:
            return None
        from sorrydave.mls.opcodes import build_commit_welcome, public_message_bytes

        if not self._signing_key_der:
            return None
        pending = getattr(self._group._group._inner, "_pending_proposals", ())
        if not pending:
            return None
        try:
            commit_bytes, welcomes, staged = stage_commit_and_welcome(
                self._group, self._signing_key_der
            )
        except Exception:
            return None
        self._outbound_staged_commits[public_message_bytes(commit_bytes)] = staged
        if self._current_epoch == 0:
            self._initial_commit_bytes = commit_bytes
        welcome_bytes = welcomes[0] if welcomes else None
        return build_commit_welcome(commit_bytes, welcome_bytes)

    def handle_proposals(self, proposal_bytes: bytes) -> Union[bytes, None]:
        """
        Process opcode 27 (proposals). Creates commit and optional welcome when applicable.

        Prefer :meth:`apply_proposals` plus a delayed :meth:`take_commit_welcome` so
        multiple opcode 27 messages in one epoch become a single commit.

        Args:
            proposal_bytes (bytes): Serialized proposals message (opcode 27 payload).

        Returns:
            Union[bytes, None]: Opcode 28 (commit/welcome) payload if commit was created, else None.
        """
        summary = self.apply_proposals(proposal_bytes)
        if summary["applied"] == 0 and summary["revoked"] == 0:
            return None
        return self.take_commit_welcome()

    def handle_commit(self, _transition_id: int, commit_bytes: bytes) -> None:
        """
        Process opcode 29: apply commit to group and refresh receive ratchets.

        Args:
            transition_id (int): Transition identifier from the announce.
            commit_bytes (bytes): Serialized MLS commit message.

        Raises:
            InvalidCommitError: If no group exists or commit application fails.
        """
        from rfc9420 import get_commit_sender_leaf_index

        from sorrydave.mls.group_state import apply_commit
        from sorrydave.mls.opcodes import public_message_bytes

        if self._group is None:
            raise InvalidCommitError("No group to apply commit to")
        incoming = public_message_bytes(commit_bytes)
        staged = self._outbound_staged_commits.get(incoming)
        own_initial = staged is not None and self._current_epoch == 0
        # Client Commit Validity: without an established group (epoch > 0),
        # refuse every commit except the one we produced for our local group.
        # Foreign op29 is for existing members; pending joiners wait for op30.
        if self._current_epoch == 0 and not own_initial:
            self._outbound_staged_commits.clear()
            self._initial_commit_bytes = None
            return
        was_unestablished = self._current_epoch == 0
        try:
            if staged is not None:
                apply_staged_commit(self._group, staged)
            else:
                sender_leaf_index = get_commit_sender_leaf_index(incoming)
                apply_commit(self._group, incoming, sender_leaf_index)
        finally:
            self._outbound_staged_commits.clear()
        self._initial_commit_bytes = None
        self._current_epoch += 1
        self._wait_for_welcome = False
        self._refresh_receive_ratchets()
        if was_unestablished:
            self._refresh_send_ratchet()

    def handle_welcome(self, _transition_id: int, welcome_bytes: bytes) -> None:
        """
        Process opcode 30: join group from welcome (we were added).

        Args:
            transition_id (int): Transition identifier from the welcome message.
            welcome_bytes (bytes): Serialized MLS Welcome message.

        Raises:
            ValueError: If no HPKE private key is available to process the welcome.
            InvalidCommitError: If the welcome cannot be processed or the resulting
                group fails DAVE validation (same recovery path as handle_commit).
        """
        from sorrydave.mls.group_state import join_from_welcome

        if self._hpke_private_key is None:
            raise ValueError("No HPKE private key; cannot process welcome")
        if self._external_sender is None:
            raise ValueError("No external sender package; cannot validate welcome group")
        if self._crypto is None:
            self._crypto = get_dave_crypto_provider()
        try:
            self._group = join_from_welcome(
                welcome_bytes,
                self._hpke_private_key,
                self._crypto,
                encryption_private_key=self._encryption_private_key,
                key_package=self._key_package_bytes,
            )
            validate_group_dave_ciphersuite_and_extensions(self._group)
            validate_group_external_sender(
                self._group,
                self._external_sender.signature_key,
                self._external_sender.credential_type,
                self._external_sender.identity,
            )
        except InvalidCommitError:
            raise
        except Exception as e:
            raise InvalidCommitError(f"Welcome could not be processed: {e}") from e
        self._outbound_staged_commits.clear()
        self._initial_commit_bytes = None
        self._current_epoch += 1
        self._wait_for_welcome = False
        self._refresh_receive_ratchets()
        self._refresh_send_ratchet()

    def set_receive_passthrough(self, enabled: bool) -> None:
        """
        Enable or disable passthrough mode on receive-side frame decryptors.

        Used for downgrade: enable when receiving dave_protocol_prepare_transition
        with protocol_version=0 so in-flight non-E2EE frames can pass through.
        """
        if self._receive_passthrough != enabled:
            self._decryptors = {}
        self._receive_passthrough = enabled

    def set_send_passthrough(self, enabled: bool) -> None:
        """
        Enable or disable passthrough mode on send-side frame encryptors.

        Used for downgrade: enable when receiving dave_protocol_execute_transition
        for a transition to protocol version 0.
        """
        if self._send_passthrough != enabled:
            self._encryptor = None
        self._send_passthrough = enabled

    def get_pending_transition(self) -> Union[tuple[int, int], None]:
        """
        Return the pending protocol transition, if any.

        After handle_prepare_transition with non-zero transition_id and
        protocol_version != 0, returns (transition_id, protocol_version) so the
        app can prepare receive decryptors and send ready_for_transition when ready.
        Cleared when execute_transition(transition_id) is called.

        Returns:
            Union[tuple[int, int], None]: (transition_id, protocol_version) or None.
        """
        if self._pending_transition_id is None or self._pending_transition_protocol_version is None:
            return None
        return (self._pending_transition_id, self._pending_transition_protocol_version)

    def handle_prepare_transition(
        self, protocol_version: int, transition_id: int
    ) -> PrepareTransitionAction:
        """
        Process opcode 21 (Prepare Transition).

        Per protocol sole member reset: when ``transition_id = 0`` and the group is
        already media-ready, the transition is executed immediately. If the group
        is not yet media-ready (epoch-1 reset / occupied join waiting for Welcome),
        execution is deferred so callers can run ``execute_transition(0)`` after
        opcode 29/30.

        For downgrade to transport-only (protocol_version=0), enables receive-side
        passthrough so in-flight frames can be passed through.

        For non-zero transition_id and protocol_version != 0, records the pending
        transition so the app can prepare receive decryptors and report ready
        via build_ready_for_transition(transition_id).

        Args:
            protocol_version (int): Protocol version for the transition.
            transition_id (int): Transition ID. 0 = execute immediately when ready.

        Returns:
            PrepareTransitionAction: ``execute_now``, ``defer_until_media_ready``,
            or ``wait_for_opcode_22``.
        """
        self._protocol_version = int(protocol_version)
        if protocol_version == 0:
            self.set_receive_passthrough(True)
        else:
            # Preparing a transition back to E2EE should clear downgrade receive passthrough.
            self.set_receive_passthrough(False)
        if transition_id == 0:
            if self.is_media_ready:
                self.execute_transition(0)
                return PREPARE_EXECUTE_NOW
            return PREPARE_DEFER_UNTIL_MEDIA_READY
        if protocol_version != 0:
            self._pending_transition_id = transition_id
            self._pending_transition_protocol_version = protocol_version
        return PREPARE_WAIT_FOR_EXECUTE

    def execute_transition(self, transition_id: int) -> None:
        """
        Process opcode 22: rotate key ratchets to new epoch.

        For downgrade to protocol version 0, enables send-side passthrough
        (receive-side was enabled on prepare_transition). For E2EE transitions,
        passthrough remains False.
        """
        if self._receive_passthrough:
            self.set_send_passthrough(True)
        else:
            self.set_receive_passthrough(False)
            self.set_send_passthrough(False)
        if self._pending_transition_id == transition_id:
            self._pending_transition_id = None
            self._pending_transition_protocol_version = None
        self._refresh_send_ratchet()
        self._refresh_receive_ratchets()

    def leave_group(self) -> Union[bytes, None]:
        """
        Tear down local MLS group state.

        Clears group, send/receive ratchets, and member state. Opcode 27 is
        gateway-to-client only; the local client does not send a Remove proposal.

        Returns:
            None: Always None. The return type is kept for API compatibility.
        """
        self._group = None
        self._send_ratchet = None
        self._receive_ratchets = {}
        self._retained_receive_ratchets = []
        self._invalidate_cryptors()
        self._member_leaf_indices = {}
        self._pending_transition_id = None
        self._pending_transition_protocol_version = None
        self._current_epoch = 0
        self._key_package_bytes = None
        self._initial_commit_bytes = None
        self._outbound_staged_commits.clear()
        return None

    def recover_from_invalid_commit(self, transition_id: int) -> tuple[bytes, bytes]:
        """
        Build opcode 31 JSON and a fresh opcode 26 key package (protocol recovery).

        After ``InvalidCommitError`` from handle_commit or handle_welcome, send the
        returned pair to the voice gateway: JSON opcode 31, then binary opcode 26.

        Args:
            transition_id (int): Transition ID from the failing opcode 29/30.

        Returns:
            tuple[bytes, bytes]: (opcode-31 JSON payload, opcode-26 key-package bytes).
        """
        from sorrydave.mls.opcodes import build_invalid_commit_welcome

        op31 = build_invalid_commit_welcome(int(transition_id))
        op26 = self.prepare_epoch(1)
        if op26 is None:
            raise RuntimeError("prepare_epoch(1) did not return a key package")
        return op31, op26

    def _refresh_send_ratchet(self) -> None:
        """
        Update send ratchet from current group exporter.

        No-op if no group is established.
        """
        if self._group is None:
            return
        from sorrydave.mls.group_state import export_sender_base_secret

        base = export_sender_base_secret(self._group, self._local_user_id)
        self._send_ratchet = KeyRatchet(base, retention_seconds=self._retention_seconds)
        self._encryptor = None

    def _refresh_receive_ratchets(self) -> None:
        """
        Refresh receive ratchets for all current senders.

        Retains previous-epoch ratchets for up to _retention_seconds so in-flight
        media from the previous epoch can still be decrypted. Then replaces the
        ratchet dict with new ratchets for the current group.
        """
        if self._group is None:
            return
        from sorrydave.mls.group_state import export_sender_base_secret

        # Retain current ratchets for transition period (protocol: up to ten seconds)
        if self._receive_ratchets:
            expiry = time.monotonic() + self._retention_seconds
            self._retained_receive_ratchets.append((expiry, dict(self._receive_ratchets)))
        # Evict expired retained ratchets
        now = time.monotonic()
        self._retained_receive_ratchets = [
            (e, d) for e, d in self._retained_receive_ratchets if e > now
        ]

        new_ratchets: dict[int, KeyRatchet] = {}
        own_leaf = self._group.own_leaf_index
        for leaf_index, identity in iter_members(self._group):
            if leaf_index == own_leaf:
                continue
            user_id = self._identity_to_user_id(identity)
            if user_id is None:
                user_id = leaf_index
            base = export_sender_base_secret(self._group, user_id)
            new_ratchets[user_id] = KeyRatchet(base, retention_seconds=self._retention_seconds)
        self._receive_ratchets = new_ratchets
        self._decryptors = {}

    @staticmethod
    def _identity_to_user_id(identity: bytes) -> Union[int, None]:
        """Extract user ID from a member's credential identity (big-endian 8-byte snowflake)."""
        if identity and len(identity) >= 8:
            return int.from_bytes(identity[:8], "big")
        return None

    def _leaf_index_to_user_id(self, leaf_index: int) -> Union[int, None]:
        """Resolve leaf index to user ID from tree credential (if available)."""
        if self._group is None:
            return None
        with contextlib.suppress(Exception):
            for li, identity in iter_members(self._group):
                if li == leaf_index:
                    return self._identity_to_user_id(identity)
        return None

    def get_epoch_authenticator(self) -> str:
        """
        Return the MLS epoch authenticator for the latest epoch as a 30-digit displayable code.

        Per protocol: displayable code with 30 digits, 6 groups of 5. Use for out-of-band
        verification that all members have the same view of the group.

        Returns:
            str: 30-digit code (e.g. for UI comparison).

        Raises:
            RuntimeError: If no group is established.
        """
        if self._group is None:
            raise RuntimeError("No group; epoch authenticator not available")
        raw = self._group._group._inner.get_epoch_authenticator()
        from sorrydave.identity import epoch_authenticator_display

        return epoch_authenticator_display(raw)

    def list_members(self) -> list[int]:
        """
        Return Discord user IDs currently in the MLS group (occupied leaves).

        Empty when no group is established. Includes the local user.
        """
        if self._group is None:
            return []
        from sorrydave.mls.group_state import iter_member_keys

        members: list[int] = []
        seen: set[int] = set()
        for _leaf, identity, _key in iter_member_keys(self._group):
            user_id = self._identity_to_user_id(identity)
            if user_id is None or user_id in seen:
                continue
            seen.add(user_id)
            members.append(user_id)
        return members

    def get_member_signature_key(self, user_id: int) -> bytes:
        """
        Return the P-256 X9.62 signature public key for a group member.

        Args:
            user_id (int): Remote (or local) Discord snowflake.

        Raises:
            RuntimeError: If no group is established.
            KeyError: If that user is not an occupied leaf.
        """
        if self._group is None:
            raise RuntimeError("No group; member signature keys not available")
        from sorrydave.mls.group_state import iter_member_keys

        want = int(user_id)
        for _leaf, identity, signature_key in iter_member_keys(self._group):
            if self._identity_to_user_id(identity) == want and signature_key:
                return signature_key
        raise KeyError(f"No signature key for user {want}")

    def get_local_signature_public_key(self) -> bytes:
        """
        Return the local P-256 X9.62 signature public key.

        Prefers the in-group leaf when established; otherwise derives the key
        from the current signing private key (after prepare_epoch(1)).
        """
        if self._group is not None:
            with contextlib.suppress(KeyError, RuntimeError):
                return self.get_member_signature_key(self._local_user_id)
        if self._signing_key_der is None:
            raise RuntimeError("No signing key; call prepare_epoch(1) first")
        from sorrydave.mls.group_state import _p256_public_from_der

        return _p256_public_from_der(self._signing_key_der)

    def get_pairwise_fingerprint(self, remote_user_id: int) -> str:
        """
        Return the 45-digit pairwise verification fingerprint for a remote member.

        Per protocol.md Identity Key Verification. Requires an established group.
        """
        from sorrydave.identity import generate_fingerprint

        remote = int(remote_user_id)
        if remote == int(self._local_user_id):
            raise ValueError("Pairwise fingerprint requires a remote user")
        local_pub = self.get_local_signature_public_key()
        remote_pub = self.get_member_signature_key(remote)
        return generate_fingerprint(self._local_user_id, local_pub, remote, remote_pub)

    def get_encryptor(self) -> FrameEncryptor:
        """
        Return encryptor for local user's outgoing frames.

        Returns:
            FrameEncryptor: Encryptor for the current send ratchet.

        Raises:
            RuntimeError: If no send ratchet (group not established).
        """
        if self._send_ratchet is None:
            self._refresh_send_ratchet()
        if self._send_ratchet is None:
            raise RuntimeError("No send ratchet; group not established")
        if self._encryptor is None:
            self._encryptor = FrameEncryptor(
                self._local_user_id,
                self._send_ratchet,
                passthrough=self._send_passthrough,
            )
        return self._encryptor

    def get_decryptor(self, sender_id: int) -> FrameDecryptor:
        """
        Return decryptor for a specific remote sender.

        Args:
            sender_id (int): Remote sender user ID.

        Returns:
            FrameDecryptor: Decryptor for that sender's frames.

        Raises:
            KeyError: If no ratchet exists for the sender.
        """
        if sender_id not in self._receive_ratchets:
            self._refresh_receive_ratchets()
        if sender_id not in self._receive_ratchets:
            raise KeyError(f"No ratchet for sender {sender_id}")
        cached = self._decryptors.get(sender_id)
        if cached is not None:
            return cached
        now = time.monotonic()
        fallbacks: list[tuple[float, KeyRatchet]] = [
            (expiry, d[sender_id])
            for expiry, d in self._retained_receive_ratchets
            if expiry > now and sender_id in d
        ]
        decryptor = FrameDecryptor(
            sender_id,
            self._receive_ratchets[sender_id],
            passthrough=self._receive_passthrough,
            fallback_ratchets=fallbacks if fallbacks else None,
        )
        self._decryptors[sender_id] = decryptor
        return decryptor

    def encrypt_frame(self, encoded_frame: bytes, codec: str) -> bytes:
        """Encrypt an encoded media frame with the local send ratchet."""
        return self.get_encryptor().encrypt(encoded_frame, codec)

    def decrypt_frame(self, protocol_frame: bytes, sender_id: int) -> bytes:
        """Decrypt a protocol frame from ``sender_id``."""
        return self.get_decryptor(int(sender_id)).decrypt(protocol_frame)


class SharedIdentityContext:
    """
    Holds a single key package and key material for use across multiple DaveSessions.

    Use when the same identity (same signature keypair) must be used for all
    concurrent voice gateway connections (e.g. voice channel and Go Live stream).
    Create one SharedIdentityContext per local user, then pass its get_supplier()
    to each DaveSession(local_user_id, identity_supplier=ctx.get_supplier()).
    """

    def __init__(
        self,
        local_user_id: int,
        crypto: Union[DefaultCryptoProvider, None] = None,
    ) -> None:
        """
        Create a shared identity context and generate one key package.

        Args:
            local_user_id (int): Local user identifier (e.g. Discord snowflake).
            crypto (Union[DefaultCryptoProvider, None]): MLS crypto provider; uses default if None.
        """
        from sorrydave.mls.group_state import create_key_package

        if crypto is None:
            crypto = get_dave_crypto_provider()
        kp_bytes, hpke_private, signing_der, encryption_private = create_key_package(
            local_user_id, crypto
        )
        self._key_package_bytes = kp_bytes
        self._hpke_private_key = hpke_private
        self._signing_key_der = signing_der
        self._encryption_private_key = encryption_private

    @classmethod
    def from_persistent_key(
        cls,
        local_user_id: int,
        private_key_der: bytes,
        crypto: Union[DefaultCryptoProvider, None] = None,
    ) -> SharedIdentityContext:
        """
        Build a shared identity from a stored persistent signature private key.

        HPKE init/encryption keys are still ephemeral per key package; only the
        MLS signature keypair is reused (protocol.md persistent identity).
        """
        from sorrydave.mls.group_state import create_key_package

        ctx = cls.__new__(cls)
        if crypto is None:
            crypto = get_dave_crypto_provider()
        kp_bytes, hpke_private, signing_der, encryption_private = create_key_package(
            local_user_id, crypto, signing_key_der=private_key_der
        )
        ctx._key_package_bytes = kp_bytes
        ctx._hpke_private_key = hpke_private
        ctx._signing_key_der = signing_der
        ctx._encryption_private_key = encryption_private
        return ctx

    def get_supplier(self) -> Callable[[], tuple[bytes, bytes, bytes, bytes]]:
        """
        Return a callable that returns
        (key_package_bytes, init_private_key, signing_key_der, encryption_private_key).

        Pass this to DaveSession(..., identity_supplier=ctx.get_supplier()).
        """
        return lambda: (
            self._key_package_bytes,
            self._hpke_private_key,
            self._signing_key_der,
            self._encryption_private_key,
        )
