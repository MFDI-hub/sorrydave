"""
DaveSession: high-level facade for DAVE media session.
Maps Voice Gateway opcodes to MLS and media transform; no I/O.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from sorrydave.crypto.ratchet import KeyRatchet
from sorrydave.media.transform import FrameDecryptor, FrameEncryptor
from sorrydave.mls.group_state import (
    create_group,
    get_dave_crypto_provider,
    validate_group_external_sender,
)
from sorrydave.mls.opcodes import ExternalSenderPackage, parse_external_sender_package

if TYPE_CHECKING:
    from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider
    from rfc9420.mls.group import Group


class DaveSession:
    """
    High-level facade for managing a DAVE media session.

    Holds MLS group state, per-sender ratchets, and provides frame encrypt/decrypt.
    """

    def __init__(self, local_user_id: int, protocol_version: int = 1):
        """
        Initialize a DAVE session for the local user.

        Args:
            local_user_id (int): Local user identifier (e.g. Discord snowflake).
            protocol_version (int): DAVE protocol version. Defaults to 1.
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
        self._retention_seconds = 10.0
        # Epoch/transition state
        self._current_epoch = 0
        self._member_leaf_indices: dict[int, int] = {}  # user_id -> leaf_index (when known)
        self._key_package_bytes: Union[bytes, None] = None
        self._group_id = b"dave-default-group"

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

        Args:
            epoch_id (int): Epoch identifier. Only epoch_id == 1 triggers key package creation.

        Returns:
            Union[bytes, None]: Opcode 26 (key package) payload if epoch_id == 1, else None.
        """
        if epoch_id != 1:
            return None
        from sorrydave.mls.group_state import create_key_package
        from sorrydave.mls.opcodes import build_key_package_message

        if self._crypto is None:
            self._crypto = get_dave_crypto_provider()
        kp_bytes, hpke_private, signing_der = create_key_package(self._local_user_id, self._crypto)
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
        if proposals_msg.operation_type != 0 or not proposals_msg.proposal_messages:
            return None
        from rfc9420.protocol.data_structures import ProposalType, Sender, SenderType
        from rfc9420.protocol.messages import MLSPlaintext as MLSPlaintextRfc

        from sorrydave.mls.opcodes import split_proposal_messages_vector

        allowed_proposal_types = {ProposalType.ADD, ProposalType.REMOVE}
        vector_blob = proposals_msg.proposal_messages[0]
        for msg_bytes in split_proposal_messages_vector(vector_blob):
            try:
                msg = MLSPlaintextRfc.deserialize(msg_bytes)
                sender = msg.auth_content.tbs.framed_content.sender
                if sender.sender_type != SenderType.EXTERNAL:
                    continue
                content = msg.auth_content.tbs.framed_content.content
                proposal_type = getattr(content, "proposal_type", None)
                if proposal_type is None:
                    type_name = type(content).__name__
                    if type_name == "AddProposal":
                        proposal_type = ProposalType.ADD
                    elif type_name == "RemoveProposal":
                        proposal_type = ProposalType.REMOVE
                if proposal_type not in allowed_proposal_types:
                    continue
                self._group._inner.process_proposal(msg, Sender(0, SenderType.EXTERNAL))
            except Exception:
                continue
        try:
            if not self._signing_key_der:
                return None
            commit_bytes, welcomes = create_commit_and_welcome(self._group, self._signing_key_der)
            welcome_bytes = welcomes[0] if welcomes else None
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
        from rfc9420.protocol.messages import MLSPlaintext

        msg = MLSPlaintext.deserialize(commit_bytes)
        sender_leaf_index = msg.auth_content.tbs.framed_content.sender.sender
        apply_commit(self._group, commit_bytes, sender_leaf_index)
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
        if self._external_sender is not None:
            validate_group_external_sender(
                self._group,
                self._external_sender.signature_key,
                self._external_sender.credential_type,
                self._external_sender.identity,
            )
        self._refresh_receive_ratchets()
        self._refresh_send_ratchet()

    def handle_prepare_transition(self, protocol_version: int, transition_id: int) -> None:
        """
        Process opcode 21 (Prepare Transition). When transition_id is 0, execute immediately.

        Per protocol sole member reset: "Upon receiving dave_protocol_prepare_transition
        with transition_id = 0, the client immediately executes the transition."

        Args:
            protocol_version (int): Protocol version for the transition.
            transition_id (int): Transition ID. 0 = execute immediately (e.g. sole member reset).
        """
        if transition_id == 0:
            self.execute_transition(0)

    def execute_transition(self, transition_id: int) -> None:
        """
        Process opcode 22: rotate key ratchets to new epoch.

        Args:
            transition_id (int): Transition identifier from execute transition payload.
        """
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
        self._member_leaf_indices = {}
        self._current_epoch = 0
        self._key_package_bytes = None
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

        Replaces the ratchet dict so removed members are dropped. No-op if no group.
        """
        if self._group is None:
            return
        from sorrydave.mls.group_state import export_sender_base_secret

        new_ratchets: dict[int, KeyRatchet] = {}
        n = self._group._inner.get_member_count()
        for leaf_index in range(n):
            if leaf_index == self._group._inner._own_leaf_index:
                continue
            user_id = self._leaf_index_to_user_id(leaf_index)
            if user_id is None:
                user_id = leaf_index
            base = export_sender_base_secret(self._group, user_id)
            new_ratchets[user_id] = KeyRatchet(base, retention_seconds=self._retention_seconds)
        self._receive_ratchets = new_ratchets

    def _leaf_index_to_user_id(self, leaf_index: int) -> Union[int, None]:
        """Resolve leaf index to user ID from tree credential (if available)."""
        if self._group is None:
            return None
        try:
            node = self._group._inner._ratchet_tree.get_node(leaf_index * 2)
            if node and node.leaf_node and node.leaf_node.credential:
                identity = node.leaf_node.credential.identity
                if len(identity) >= 8:
                    return int.from_bytes(identity[:8], "big")
        except Exception:
            pass
        return None

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
        return FrameEncryptor(self._local_user_id, self._send_ratchet)

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
        return FrameDecryptor(sender_id, self._receive_ratchets[sender_id])
