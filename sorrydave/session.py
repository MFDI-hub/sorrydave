"""
DaveSession: high-level facade for DAVE media session.
Maps Voice Gateway opcodes to MLS and media transform; no I/O.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Callable, Union

from sorrydave.crypto.ratchet import KeyRatchet
from sorrydave.media.transform import FrameDecryptor, FrameEncryptor
from sorrydave.mls.group_state import (
    create_group,
    get_dave_crypto_provider,
    validate_group_dave_ciphersuite_and_extensions,
    validate_group_external_sender,
)
from sorrydave.mls.opcodes import ExternalSenderPackage, parse_external_sender_package

if TYPE_CHECKING:
    from sorrydave._rfc9420 import DefaultCryptoProvider, Group


class DaveSession:
    """
    High-level facade for managing a DAVE media session.

    Holds MLS group state, per-sender ratchets, and provides frame encrypt/decrypt.
    Performs no I/O; you pass in bytes (opcode payloads, encoded frames) and get back bytes.

    Typical usage:
        1. Create: DaveSession(local_user_id=...).
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
        identity_supplier: Union[Callable[[], tuple[bytes, bytes, bytes]], None] = None,
    ):
        """
        Initialize a DAVE session for the local user.

        Args:
            local_user_id (int): Local user identifier (e.g. Discord snowflake).
            protocol_version (int): DAVE protocol version. Defaults to 1.
            identity_supplier (Union[Callable[[], tuple[bytes, bytes, bytes]], None]): Optional
                callable that returns (key_package_bytes, hpke_private_key, signing_key_der) to use
                the same identity across multiple sessions (e.g. voice channel + Go Live). When set,
                prepare_epoch(1) uses it instead of generating a new key package. Use
                SharedIdentityContext to share one keypair across sessions.
        """
        self._local_user_id = local_user_id
        self._protocol_version = protocol_version
        self._group: Union[Group, None] = None
        self._crypto: Union[DefaultCryptoProvider, None] = None
        self._hpke_private_key: Union[bytes, None] = None
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
        self._group_id = b"dave-default-group"
        # Optional shared identity: same keypair across concurrent voice gateway connections
        self._identity_supplier: Union[Callable[[], tuple[bytes, bytes, bytes]], None] = (
            identity_supplier
        )
        # Expected media session members (from opcodes 11/13); add proposals are validated against this
        self._expected_member_ids: set[int] = set()
        # Client commit validity: when epoch is 0, only accept commit that matches our initial local group commit
        self._initial_commit_bytes: Union[bytes, None] = None

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
        self._current_epoch = 0

        from sorrydave.mls.opcodes import build_key_package_message

        if self._identity_supplier is not None:
            kp_bytes, hpke_private, signing_der = self._identity_supplier()
        else:
            from sorrydave.mls.group_state import create_key_package

            if self._crypto is None:
                self._crypto = get_dave_crypto_provider()
            kp_bytes, hpke_private, signing_der = create_key_package(
                self._local_user_id, self._crypto
            )
        self._hpke_private_key = hpke_private
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

    def add_expected_members(self, user_ids: Iterable[Union[int, str]]) -> None:
        """
        Add user IDs to the set of expected media session members.

        Call after receiving opcode 11 (clients_connect). Add proposals for users
        not in this set will be refused when the set is non-empty.
        """
        for uid in user_ids:
            self._expected_member_ids.add(int(uid))

    def remove_expected_member(self, user_id: Union[int, str]) -> None:
        """
        Remove a user ID from the set of expected media session members.

        Call after receiving opcode 13 (client_disconnect). That user will not be
        accepted in add proposals until they appear again in clients_connect.
        """
        self._expected_member_ids.discard(int(user_id))

    def handle_proposals(self, proposal_bytes: bytes) -> Union[bytes, None]:
        """
        Process opcode 27 (proposals). Creates commit and optional welcome when applicable.

        Args:
            proposal_bytes (bytes): Serialized proposals message (opcode 27 payload).

        Returns:
            Union[bytes, None]: Opcode 28 (commit/welcome) payload if commit was created, else None.
        """
        if self._group is None:
            return None
        from sorrydave.mls.group_state import create_commit_and_welcome
        from sorrydave.mls.opcodes import build_commit_welcome, parse_proposals

        try:
            proposals_msg = parse_proposals(proposal_bytes)
        except Exception:
            return None
        # Revoke: remove cached proposals by ref (protocol: voice gateway may revoke in-flight proposals)
        if proposals_msg.operation_type == 1:
            if proposals_msg.proposal_refs:
                for ref in proposals_msg.proposal_refs:
                    try:
                        self._group.revoke_proposal(ref)
                    except Exception:
                        pass
            return None
        if proposals_msg.operation_type != 0 or not proposals_msg.proposal_messages:
            return None
        from sorrydave._rfc9420 import (
            AddProposal,
            KeyPackage,
            MLSPlaintext as MLSPlaintextRfc,
            Proposal,
            ProposalType,
            SenderType,
        )

        allowed_proposal_types = {ProposalType.ADD, ProposalType.REMOVE}
        vector_blob = proposals_msg.proposal_messages[0]

        # Discord sends the proposals vector as concatenated MLSPlaintext
        # structures (no per-element varint length prefix). Parse them directly.
        mls_messages: list[MLSPlaintextRfc] = []
        try:
            msg = MLSPlaintextRfc.deserialize(vector_blob)
            mls_messages.append(msg)
        except Exception:
            # Fallback: try opaque<V> splitting for forward compatibility.
            from sorrydave.mls.opcodes import split_proposal_messages_vector
            for chunk in split_proposal_messages_vector(vector_blob):
                try:
                    mls_messages.append(MLSPlaintextRfc.deserialize(chunk))
                except Exception:
                    continue

        for msg in mls_messages:
            try:
                sender = msg.auth_content.tbs.framed_content.sender
                if sender.sender_type != SenderType.EXTERNAL:
                    continue
                content_bytes = msg.auth_content.tbs.framed_content.content
                try:
                    proposal = Proposal.deserialize(content_bytes)
                except Exception:
                    continue
                proposal_type = proposal.proposal_type
                if proposal_type not in allowed_proposal_types:
                    continue
                if proposal_type == ProposalType.ADD and self._expected_member_ids:
                    try:
                        if not isinstance(proposal, AddProposal):
                            continue
                        kp = KeyPackage.deserialize(proposal.key_package)
                        if (
                            kp.leaf_node
                            and kp.leaf_node.credential
                            and kp.leaf_node.credential.identity
                        ):
                            add_user_id = int.from_bytes(
                                kp.leaf_node.credential.identity[:8], "big"
                            )
                            if add_user_id not in self._expected_member_ids:
                                continue
                    except Exception:
                        continue
                self._group.process_proposal(
                    msg, sender_leaf_index=0, sender_type=SenderType.EXTERNAL
                )
            except Exception:
                continue
        try:
            if not self._signing_key_der:
                return None
            commit_bytes, welcomes = create_commit_and_welcome(self._group, self._signing_key_der)
            welcome_bytes = welcomes[0] if welcomes else None
            if self._current_epoch == 0:
                self._initial_commit_bytes = commit_bytes
            return build_commit_welcome(commit_bytes, welcome_bytes)
        except Exception:
            return None

    def handle_commit(self, transition_id: int, commit_bytes: bytes) -> None:
        """
        Process opcode 29: apply commit to group and refresh receive ratchets.

        Args:
            transition_id (int): Transition identifier from the announce.
            commit_bytes (bytes): Serialized MLS commit message.

        Raises:
            InvalidCommitError: If no group exists or commit application fails.
        """
        from sorrydave.exceptions import InvalidCommitError
        from sorrydave.mls.group_state import apply_commit

        if self._group is None:
            raise InvalidCommitError("No group to apply commit to")
        # Client commit validity (protocol.md): epoch 0 → only accept our own initial commit;
        # apply_commit also enforces that all proposals are references (no inline proposals).
        if self._current_epoch == 0 and self._initial_commit_bytes is not None:
            if commit_bytes != self._initial_commit_bytes:
                raise InvalidCommitError("Commit does not match initial local group commit")
        apply_commit(self._group, commit_bytes)
        self._initial_commit_bytes = None
        self._current_epoch += 1
        self._refresh_receive_ratchets()

    def handle_welcome(self, transition_id: int, welcome_bytes: bytes) -> None:
        """
        Process opcode 30: join group from welcome (we were added).

        Args:
            transition_id (int): Transition identifier from the welcome message.
            welcome_bytes (bytes): Serialized MLS Welcome message.

        Raises:
            ValueError: If no HPKE private key is available to process the welcome.
        """
        from sorrydave.mls.group_state import join_from_welcome

        if self._hpke_private_key is None:
            raise ValueError("No HPKE private key; cannot process welcome")
        if self._crypto is None:
            self._crypto = get_dave_crypto_provider()
        self._group = join_from_welcome(welcome_bytes, self._hpke_private_key, self._crypto)
        validate_group_dave_ciphersuite_and_extensions(self._group)
        if self._external_sender is not None:
            validate_group_external_sender(
                self._group,
                self._external_sender.signature_key,
                self._external_sender.credential_type,
                self._external_sender.identity,
            )
        self._current_epoch += 1
        self._refresh_receive_ratchets()
        self._refresh_send_ratchet()

    def set_receive_passthrough(self, enabled: bool) -> None:
        """
        Enable or disable passthrough mode on receive-side frame decryptors.

        Used for downgrade: enable when receiving dave_protocol_prepare_transition
        with protocol_version=0 so in-flight non-E2EE frames can pass through.
        """
        self._receive_passthrough = enabled

    def set_send_passthrough(self, enabled: bool) -> None:
        """
        Enable or disable passthrough mode on send-side frame encryptors.

        Used for downgrade: enable when receiving dave_protocol_execute_transition
        for a transition to protocol version 0.
        """
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

    def handle_prepare_transition(self, protocol_version: int, transition_id: int) -> None:
        """
        Process opcode 21 (Prepare Transition). When transition_id is 0, execute immediately.

        Per protocol sole member reset: "Upon receiving dave_protocol_prepare_transition
        with transition_id = 0, the client immediately executes the transition."

        For downgrade to transport-only (protocol_version=0), enables receive-side
        passthrough so in-flight frames can be passed through.

        For non-zero transition_id and protocol_version != 0, records the pending
        transition so the app can prepare receive decryptors and report ready
        via build_ready_for_transition(transition_id).

        Args:
            protocol_version (int): Protocol version for the transition.
            transition_id (int): Transition ID. 0 = execute immediately (e.g. sole member reset).
        """
        if protocol_version == 0:
            self.set_receive_passthrough(True)
        if transition_id == 0:
            self.execute_transition(0)
            return
        if protocol_version != 0:
            self._pending_transition_id = transition_id
            self._pending_transition_protocol_version = protocol_version

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
        Tear down local MLS group state and optionally return a Remove proposal for self.

        Clears group, send/receive ratchets, and member state.

        Returns:
            Union[bytes, None]: Serialized Remove proposal bytes to send (e.g. via opcode 27)
                if session had a group and signing key; otherwise None.
        """
        remove_proposal_bytes: Union[bytes, None] = None
        if self._group is not None and self._signing_key_der is not None:
            try:
                from sorrydave.mls.group_state import create_remove_proposal_for_self

                remove_proposal_bytes = create_remove_proposal_for_self(
                    self._group, self._signing_key_der
                )
            except Exception:
                pass
        self._group = None
        self._send_ratchet = None
        self._receive_ratchets = {}
        self._retained_receive_ratchets = []
        self._member_leaf_indices = {}
        self._pending_transition_id = None
        self._pending_transition_protocol_version = None
        self._current_epoch = 0
        self._key_package_bytes = None
        self._initial_commit_bytes = None
        return remove_proposal_bytes

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
        for leaf_index, identity in self._group.iter_members():
            if leaf_index == own_leaf:
                continue
            user_id = self._identity_to_user_id(identity)
            if user_id is None:
                user_id = leaf_index
            base = export_sender_base_secret(self._group, user_id)
            new_ratchets[user_id] = KeyRatchet(base, retention_seconds=self._retention_seconds)
        self._receive_ratchets = new_ratchets

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
        try:
            for li, identity in self._group.iter_members():
                if li == leaf_index:
                    return self._identity_to_user_id(identity)
        except Exception:
            pass
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
        raw = self._group._inner.get_epoch_authenticator()
        from sorrydave.identity import epoch_authenticator_display

        return epoch_authenticator_display(raw)

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
        return FrameEncryptor(
            self._local_user_id,
            self._send_ratchet,
            passthrough=self._send_passthrough,
        )

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
        now = time.monotonic()
        fallbacks: list[tuple[float, KeyRatchet]] = [
            (expiry, d[sender_id])
            for expiry, d in self._retained_receive_ratchets
            if expiry > now and sender_id in d
        ]
        return FrameDecryptor(
            sender_id,
            self._receive_ratchets[sender_id],
            passthrough=self._receive_passthrough,
            fallback_ratchets=fallbacks if fallbacks else None,
        )


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
        kp_bytes, hpke_private, signing_der = create_key_package(local_user_id, crypto)
        self._key_package_bytes = kp_bytes
        self._hpke_private_key = hpke_private
        self._signing_key_der = signing_der

    def get_supplier(self) -> Callable[[], tuple[bytes, bytes, bytes]]:
        """
        Return a callable that returns (key_package_bytes, hpke_private_key, signing_key_der).

        Pass this to DaveSession(..., identity_supplier=ctx.get_supplier()).
        """
        return lambda: (
            self._key_package_bytes,
            self._hpke_private_key,
            self._signing_key_der,
        )
