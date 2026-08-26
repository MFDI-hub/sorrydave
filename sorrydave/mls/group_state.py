"""
MLS group state manager: rfc9420 integration for DAVE.

Creates group, key package, processes commit/welcome, exports sender base secret.
Used by DaveSession for group lifecycle; can also be used for custom flows.

Public functions:
    get_dave_crypto_provider: DAVE MLS ciphersuite crypto provider.
    create_key_package: Key package for a user; used by DaveSession.prepare_epoch(1).
    create_group: New MLS group with one member; used when handling opcode 25.
    join_from_welcome: Join from Welcome message; used by DaveSession.handle_welcome.
    export_sender_base_secret: 16-byte base secret for KeyRatchet; used when refreshing ratchets.
    apply_commit: Apply received commit; used by DaveSession.handle_commit.
    process_proposal: Apply one proposal; used by DaveSession.handle_proposals.
    create_commit_and_welcome: Build commit and welcomes; used by DaveSession.handle_proposals.
    create_remove_proposal_for_self: Optional self-remove helper (not sent as opcode 27).
    create_update_proposal: Update proposal to refresh leaf keys; optional.
    validate_group_dave_ciphersuite_and_extensions: Check ciphersuite and extension list for DAVE.
    validate_group_external_sender: Check external sender matches; used when applying commits.
    get_external_senders_from_group: Read external senders from group context.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator
from typing import Any, Union

from rfc9420 import DefaultCryptoProvider, MLSGroup, SenderType
from rfc9420.api.session import MLSGroupSession
from rfc9420.extensions.extensions import ExtensionType

from sorrydave.exceptions import InvalidCommitError

# DAVE protocol v1: MLS ciphersuite 2 (DHKEMP256_AES128GCM_SHA256_P256)
DAVE_MLS_CIPHERSUITE_ID = 2
EXPORTER_LABEL = b"Discord Secure Frames v0"
EXPORTER_LENGTH = 16
EXTENSION_TYPE_EXTERNAL_SENDERS = int(ExtensionType.EXTERNAL_SENDERS)
_LEAF_NODE_TBS_LABEL = b"LeafNodeTBS"
_KEY_PACKAGE_TBS_LABEL = b"KeyPackageTBS"
_PROPOSAL_VALIDATION_PATCH_LOCK = threading.RLock()


@contextlib.contextmanager
def _rfc9420_dave_commit_interop() -> Iterator[None]:
    """Compat shim for rfc9420 versions that disagree with Discord KeyPackages.

    Current PyMLS treats RFC 9420 §7.2 default types (including
    ``external_senders``) as always supported and does not GREASE GroupInfo.
    Older rfc9420 1.2.0 hashed neither of those; patch only then.
    """
    from rfc9420.extensions import extensions as mls_extensions

    if hasattr(mls_extensions, "leaf_supports_group_extension"):
        yield
        return

    from unittest.mock import patch

    from rfc9420.extensions.extensions import parse_capabilities_data as _parse_caps
    from rfc9420.group.mls_group import processing as mls_processing

    def _inject_external_senders(caps: dict[str, Any]) -> dict[str, Any]:
        exts = list(caps.get("extensions") or [])
        if EXTENSION_TYPE_EXTERNAL_SENDERS not in exts:
            exts.append(EXTENSION_TYPE_EXTERNAL_SENDERS)
        caps["extensions"] = exts
        return caps

    def _parse_caps_allow_external_senders(
        data: bytes, return_consumed: bool = False
    ) -> dict[str, Any] | tuple[dict[str, Any], int]:
        if return_consumed:
            parsed = _parse_caps(data, return_consumed=True)
            caps, consumed = parsed if isinstance(parsed, tuple) else (parsed, 0)
            return _inject_external_senders(caps), consumed
        parsed = _parse_caps(data)
        caps = parsed[0] if isinstance(parsed, tuple) else parsed
        return _inject_external_senders(caps)

    with (
        patch.object(mls_processing, "parse_capabilities_data", _parse_caps_allow_external_senders),
        patch.object(mls_extensions, "random_grease_values", lambda *_a, **_k: []),
    ):
        yield


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read MLS-style varint from data at offset. Returns (value, new_offset)."""
    if offset >= len(data):
        raise ValueError("Varint truncated")
    first = data[offset]
    prefix = first >> 6
    if prefix == 0b00:
        return first & 0x3F, offset + 1
    if prefix == 0b01:
        if offset + 2 > len(data):
            raise ValueError("Varint truncated")
        value = ((first & 0x3F) << 8) | data[offset + 1]
        return value, offset + 2
    if prefix == 0b10:
        if offset + 4 > len(data):
            raise ValueError("Varint truncated")
        value = (
            ((first & 0x3F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3]
        )
        return value, offset + 4
    raise ValueError("Varint overflow")


def _read_opaque_varint(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read opaque<V>: varint length then that many bytes."""
    length, pos = _read_varint(data, offset)
    if pos + length > len(data):
        raise ValueError("Opaque truncated")
    return data[pos : pos + length], pos + length


def get_dave_crypto_provider() -> DefaultCryptoProvider:
    """
    Return rfc9420 DefaultCryptoProvider with DAVE MLS ciphersuite (2).

    Used by DaveSession when creating key packages and groups.

    Returns:
        DefaultCryptoProvider: Instance for DHKEMP256_AES128GCM_SHA256_P256.
    """
    return DefaultCryptoProvider(suite_id=DAVE_MLS_CIPHERSUITE_ID)


def _dave_capabilities() -> bytes:
    """LeafNode capabilities matching Discord / RFC 9420 default-type rules.

    RFC 9420 §7.2: default proposal types (Add, Remove, …) and default
    extension types (including external_senders) MUST NOT be listed.
    Live Discord KeyPackages advertise versions=[1], ciphersuites=[2],
    extensions=[], proposals=[], credentials=[1].
    """
    from rfc9420.extensions.extensions import build_capabilities_data
    from rfc9420.messages.data_structures import CredentialType

    kwargs: dict[str, Any] = {
        "ciphersuite_ids": [DAVE_MLS_CIPHERSUITE_ID],
        "supported_exts": [],
        "proposals": [],
        "credentials": [int(CredentialType.BASIC)],
    }
    try:
        return build_capabilities_data(**kwargs, include_grease=False)
    except TypeError:
        return build_capabilities_data(**kwargs)


def _p256_signing_keypair() -> tuple[bytes, bytes]:
    """Return (PKCS8 DER private key, uncompressed X962 public key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    sig_private = ec.generate_private_key(ec.SECP256R1())
    sig_private_der = sig_private.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    sig_public_bytes = sig_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    if sig_public_bytes[0] != 0x04:
        sig_public_bytes = b"\x04" + sig_public_bytes
    return sig_private_der, sig_public_bytes


def _dave_cipher_suite():
    from rfc9420.crypto.ciphersuites import get_ciphersuite_by_id
    from rfc9420.messages.data_structures import CipherSuite

    cs = get_ciphersuite_by_id(DAVE_MLS_CIPHERSUITE_ID)
    if cs is None:
        raise ValueError(f"Unknown MLS ciphersuite id {DAVE_MLS_CIPHERSUITE_ID}")
    return CipherSuite(cs.kem, cs.kdf, cs.aead, suite_id=cs.suite_id)


def create_key_package(
    user_id: int,
    crypto: Union[DefaultCryptoProvider, None] = None,
) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Create a KeyPackage for the given user_id (64-bit e.g. Discord snowflake).

    Used by DaveSession when prepare_epoch(1) is called. Identity is big-endian user_id (8 bytes).
    Lifetime not_before=0, not_after=2^64-1.

    rfc9420 1.2.0 requires a distinct HPKE init_key from the leaf encryption_key
    (RFC 9420 §10.1) and SignWithLabel for LeafNodeTBS / KeyPackageTBS.

    Args:
        user_id (int): User identifier (64-bit).
        crypto (Union[DefaultCryptoProvider, None]): Crypto provider; uses get_dave_crypto_provider() if None.

    Returns:
        tuple[bytes, bytes, bytes, bytes]:
            (key_package_serialized, init_private_key, signing_key_der, encryption_private_key).
            ``init_private_key`` decrypts Welcome; ``encryption_private_key`` decrypts later UpdatePaths.

    Raises:
        ValueError: If MLS ciphersuite is unknown.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()

    from rfc9420.messages.data_structures import (
        Credential,
        CredentialType,
        MLSVersion,
        Signature,
    )
    from rfc9420.messages.key_packages import KeyPackage, LeafNode, LeafNodeSource

    cipher_suite = _dave_cipher_suite()
    init_private, init_public = crypto.generate_key_pair()
    enc_private, enc_public = crypto.generate_key_pair()
    sig_private_der, sig_public_bytes = _p256_signing_keypair()
    identity = user_id.to_bytes(8, "big")
    credential = Credential(
        identity=identity,
        public_key=sig_public_bytes,
        credential_type=CredentialType.BASIC,
    )
    capabilities = _dave_capabilities()
    lifetime_not_before = 0
    lifetime_not_after = (1 << 64) - 1
    leaf_node = LeafNode(
        encryption_key=enc_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.KEY_PACKAGE,
        lifetime_not_before=lifetime_not_before,
        lifetime_not_after=lifetime_not_after,
        parent_hash=b"",
        extensions=[],
        signature=Signature(b""),
    )
    leaf_tbs = leaf_node.tbs_serialize()
    leaf_sig = crypto.sign_with_label(sig_private_der, _LEAF_NODE_TBS_LABEL, leaf_tbs)
    leaf_node = LeafNode(
        encryption_key=enc_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.KEY_PACKAGE,
        lifetime_not_before=lifetime_not_before,
        lifetime_not_after=lifetime_not_after,
        parent_hash=b"",
        extensions=[],
        signature=Signature(leaf_sig),
    )
    kp = KeyPackage(
        version=MLSVersion.MLS10,
        cipher_suite=cipher_suite,
        init_key=init_public,
        leaf_node=leaf_node,
        extensions=[],
        signature=Signature(b""),
    )
    kp_tbs = kp.tbs_serialize()
    kp_sig = crypto.sign_with_label(sig_private_der, _KEY_PACKAGE_TBS_LABEL, kp_tbs)
    kp = KeyPackage(
        version=MLSVersion.MLS10,
        cipher_suite=cipher_suite,
        init_key=init_public,
        leaf_node=leaf_node,
        extensions=[],
        signature=Signature(kp_sig),
    )
    return (kp.serialize(), init_private, sig_private_der, enc_private)


def _write_varint(x: int) -> bytes:
    """RFC 9420 variable-length integer encoding."""
    if x < 0x40:
        return bytes([x])
    if x < 0x4000:
        return (x | 0x4000).to_bytes(2, "big")
    if x <= 0x3FFFFFFF:
        return (x | 0x80000000).to_bytes(4, "big")
    raise ValueError("integer too large for RFC 9420 varint")


def _write_opaque_varint(data: bytes) -> bytes:
    """Encode opaque<V>: varint length prefix + data."""
    return _write_varint(len(data)) + data


def serialize_external_senders_extension(
    signature_key: bytes,
    credential_type: int,
    identity: bytes,
) -> bytes:
    """Serialize the external_senders group extension for the MLS GroupContext.

    Returns concatenated Extension encodings (no outer vector length prefix),
    matching rfc9420 ``serialize_extensions``.

    Wire format per RFC 9420 section 12.1.8.1 / §17.3 (external_senders = 0x0005):
        Extension { uint16 extension_type; opaque extension_data<V>; }
        ExternalSendersExtension { ExternalSender external_senders<V>; }
        ExternalSender { SignaturePublicKey signature_key; Credential credential; }
        Credential { uint16 credential_type; opaque identity<V>; }
    """
    from rfc9420.codec.tls import write_opaque_varint, write_uint16
    from rfc9420.extensions.extensions import Extension, serialize_extensions

    entry = write_opaque_varint(signature_key)
    entry += write_uint16(credential_type)
    entry += write_opaque_varint(identity)
    ext = Extension(EXTENSION_TYPE_EXTERNAL_SENDERS, entry)
    return serialize_extensions([ext])


def get_external_senders_from_group(session: MLSGroupSession) -> list[tuple[bytes, int, bytes]]:
    """
    Parse GroupContext.extensions and return list of (signature_key, credential_type, identity)
    for the external_senders extension.

    Note: Uses ``session._group._inner._group_context`` because the rfc9420 public API
    does not expose group context extensions. Required for protocol-mandated external
    sender validation (protocol.md §Invalid Groups).

    Returns:
        list[tuple[bytes, int, bytes]]: Empty if no external senders extension or parse error.
    """
    from rfc9420.codec.tls import read_opaque_varint, read_uint16
    from rfc9420.extensions.extensions import deserialize_extensions, parse_external_senders

    try:
        inner = session._group._inner
        gc = inner._group_context
        if gc is None or not gc.extensions:
            return []
    except Exception:
        return []
    data = gc.extensions if isinstance(gc.extensions, bytes) else b""
    if not data:
        return []
    try:
        result: list[tuple[bytes, int, bytes]] = []
        for ext in deserialize_extensions(data):
            if int(ext.ext_type) != EXTENSION_TYPE_EXTERNAL_SENDERS:
                continue
            for sender in parse_external_senders(ext.data):
                cred_type, off = read_uint16(sender.credential_data, 0)
                identity, _off = read_opaque_varint(sender.credential_data, off)
                result.append((sender.signature_key, cred_type, identity))
        return result
    except Exception:
        return []


def validate_group_dave_ciphersuite_and_extensions(session: MLSGroupSession) -> None:
    """
    Verify the group has the expected DAVE ciphersuite and extension list (protocol version).

    Per protocol: group must have expected ciphersuite and extension list (external_senders only).

    Raises:
        InvalidCommitError: If ciphersuite is not DAVE or extensions are not exactly external_senders.
    """
    from rfc9420.extensions.extensions import deserialize_extensions

    try:
        inner = session._group._inner
        gc = inner._group_context
        if gc is None:
            raise InvalidCommitError("Group has no group context")
        if getattr(gc, "cipher_suite_id", None) != DAVE_MLS_CIPHERSUITE_ID:
            raise InvalidCommitError(
                f"Group ciphersuite must be {DAVE_MLS_CIPHERSUITE_ID}; got {getattr(gc, 'cipher_suite_id', None)}"
            )
        data = gc.extensions if isinstance(gc.extensions, bytes) else b""
        if not data:
            raise InvalidCommitError("Group must have exactly one extension (external_senders)")
        exts = deserialize_extensions(data)
        if len(exts) != 1:
            raise InvalidCommitError(
                f"Group must have exactly one extension (external_senders); got {len(exts)}"
            )
        ext_type = int(exts[0].ext_type)
        if ext_type != EXTENSION_TYPE_EXTERNAL_SENDERS:
            raise InvalidCommitError(
                f"Group extension must be external_senders (0x{EXTENSION_TYPE_EXTERNAL_SENDERS:04x}); got 0x{ext_type:04x}"
            )
    except InvalidCommitError:
        raise
    except Exception as e:
        raise InvalidCommitError("Invalid group ciphersuite or extensions") from e


def validate_group_external_sender(
    session: MLSGroupSession,
    expected_signature_key: bytes,
    expected_credential_type: int,
    expected_identity: bytes,
) -> None:
    """
    Verify the group has exactly one external sender matching the voice gateway package.

    Raises:
        InvalidCommitError: If not exactly one external sender or no match.
    """
    senders = get_external_senders_from_group(session)
    if len(senders) != 1:
        raise InvalidCommitError(f"Group must have exactly one external sender; got {len(senders)}")
    sig_key, cred_type, identity = senders[0]
    if (
        sig_key != expected_signature_key
        or cred_type != expected_credential_type
        or identity != expected_identity
    ):
        raise InvalidCommitError("Group external sender does not match voice gateway package")


def create_group(
    group_id: bytes,
    key_package_bytes: bytes,
    crypto: Union[DefaultCryptoProvider, None] = None,
    external_sender_signature_key: Union[bytes, None] = None,
    external_sender_credential_type: int = 1,
    external_sender_identity: Union[bytes, None] = None,
) -> MLSGroupSession:
    """
    Create a new MLS group with the given key package (single member).

    Used by DaveSession when handle_external_sender_package is called and a key package
    was already prepared. When external sender parameters are provided, the group
    extensions include the required external_senders extension per
    RFC 9420 section 12.1.8.1. This is mandatory for the DAVE protocol.
    """
    from rfc9420 import GroupConfig, MemoryStorageProvider
    from rfc9420.api.session import MLSGroupSession
    from rfc9420.messages.key_packages import KeyPackage

    if crypto is None:
        crypto = get_dave_crypto_provider()
    storage = MemoryStorageProvider()
    config = GroupConfig(crypto_provider=crypto, storage_provider=storage)

    initial_extensions = b""
    if external_sender_signature_key is not None and external_sender_identity is not None:
        initial_extensions = serialize_external_senders_extension(
            signature_key=external_sender_signature_key,
            credential_type=external_sender_credential_type,
            identity=external_sender_identity,
        )

    kp = KeyPackage.deserialize(key_package_bytes)
    return MLSGroupSession.create_with_config(
        config, group_id, kp, initial_extensions=initial_extensions
    )


def join_from_welcome(
    welcome_bytes: bytes,
    hpke_private_key: bytes,
    crypto: Union[DefaultCryptoProvider, None] = None,
    encryption_private_key: Union[bytes, None] = None,
    key_package: Union[bytes, None] = None,
) -> MLSGroupSession:
    """
    Join group from Welcome message.

    Used by DaveSession when handle_welcome is called (client was added to the group).

    Args:
        welcome_bytes (bytes): Serialized MLS Welcome message.
        hpke_private_key (bytes): HPKE private key for KeyPackage.init_key (Welcome decrypt).
        crypto (Union[DefaultCryptoProvider, None]): Crypto provider; uses get_dave_crypto_provider() if None.
        encryption_private_key (Union[bytes, None]): HPKE private key for LeafNode.encryption_key.
            Required by rfc9420 1.2.0 to decrypt later UpdatePath ciphertexts.
        key_package (Union[bytes, None]): Optional serialized KeyPackage used to locate the joiner leaf.

    Returns:
        MLSGroupSession: Session for the joined group.
    """
    from rfc9420 import GroupConfig, MemoryStorageProvider
    from rfc9420.api.session import MLSGroupSession
    from rfc9420.group.mls_group.processing import MLSGroup as ProtocolMLSGroup
    from rfc9420.messages.data_structures import Welcome
    from rfc9420.messages.key_packages import KeyPackage

    if crypto is None:
        crypto = get_dave_crypto_provider()
    storage = MemoryStorageProvider()
    config = GroupConfig(crypto_provider=crypto, storage_provider=storage)
    welcome = Welcome.deserialize(welcome_bytes)
    kp_obj = KeyPackage.deserialize(key_package) if key_package is not None else None
    inner = ProtocolMLSGroup.from_welcome(
        welcome=welcome,
        hpke_private_key=hpke_private_key,
        crypto_provider=crypto,
        rand_provider=config.resolved_rand_provider(),
        secret_tree_window_size=config.secret_tree_window_size,
        max_generation_gap=config.max_generation_gap,
        aead_limit_bytes=config.aead_limit_bytes,
        tree_backend=config.tree_backend_id,
        key_package=kp_obj,
        encryption_private_key=encryption_private_key,
    )
    return MLSGroupSession(MLSGroup(config, inner))


def export_sender_base_secret(session: MLSGroupSession, sender_user_id: int) -> bytes:
    """
    Export 16-byte sender base secret via MLS Exporter.

    Used by DaveSession when refreshing send/receive ratchets (KeyRatchet base secret).
    Uses label "Discord Secure Frames v0" and context = little-endian 64-bit sender user ID.

    RFC 9420 §8.5 hashes Context before ExpandWithLabel.  Compute the exporter
    directly because rfc9420 1.2.0 incorrectly passes the raw context.

    Args:
        session (MLSGroupSession): MLS group session.
        sender_user_id (int): Sender user ID (64-bit).

    Returns:
        bytes: 16-byte base secret for KeyRatchet.
    """
    context = sender_user_id.to_bytes(8, "little")
    inner = session._group._inner
    crypto = inner._crypto_provider
    exporter_secret = inner.get_exporter_secret()
    derived = crypto.derive_secret(exporter_secret, EXPORTER_LABEL)
    context_hash = crypto.hash(context)
    result: bytes = crypto.expand_with_label(
        derived, b"exported", context_hash, EXPORTER_LENGTH
    )
    return result


def iter_members(session: MLSGroupSession) -> list[tuple[int, bytes]]:
    """
    Return (leaf_index, identity) for each member using the session's ratchet tree.

    Identity is the credential identity bytes (e.g. big-endian user ID); empty bytes if none.
    """
    with contextlib.suppress(Exception):
        result: list[tuple[int, bytes]] = session._group._inner.get_member_identities()
        return result
    return []


def _iter_members(session: MLSGroupSession) -> list[tuple[int, bytes]]:
    """Alias for iter_members used internally."""
    return iter_members(session)


def _check_no_duplicate_credentials(session: MLSGroupSession) -> None:
    """
    Raise InvalidCommitError if the group tree has duplicate basic credentials (user IDs).

    Per DAVE client commit validity: "The resulting group includes a duplicated basic
    credential (i.e. the big-endian user ID snowflake) between two or more leaf nodes."
    """
    seen: set[bytes] = set()
    try:
        for _leaf_index, identity in _iter_members(session):
            if not identity or len(identity) < 8:
                continue
            id_bytes = identity[:8]
            if id_bytes in seen:
                raise InvalidCommitError("Duplicate basic credential in group tree")
            seen.add(id_bytes)
    except InvalidCommitError:
        raise
    except Exception:
        return


def apply_commit(
    session: MLSGroupSession,
    commit_mls_plaintext_bytes: bytes,
    sender_leaf_index: int,
) -> None:
    """
    Apply a received commit to the group.

    Used by DaveSession when handle_commit is called. Per DAVE client commit validity,
    raises InvalidCommitError if the resulting group would have duplicate basic
    credentials (user IDs).

    Args:
        session (MLSGroupSession): MLS group session.
        commit_mls_plaintext_bytes (bytes): Serialized MLS Plaintext commit message.
        sender_leaf_index (int): Leaf index of the commit sender.

    Raises:
        InvalidCommitError: If commit application fails or duplicate credentials.
    """
    try:
        session.apply_commit(commit_mls_plaintext_bytes, sender_leaf_index)
        _check_no_duplicate_credentials(session)
    except InvalidCommitError:
        raise
    except Exception as e:
        raise InvalidCommitError("Failed to apply commit") from e


def process_proposal(
    session: MLSGroupSession,
    proposal_mls_plaintext_bytes: bytes,
    sender_leaf_index: int,
    sender_type: int = 1,
) -> None:
    """
    Process a proposal (e.g. Add/Remove from external sender).

    Used by DaveSession when handle_proposals is called to apply each proposal
    before creating a commit.

    Args:
        session (MLSGroupSession): MLS group session.
        proposal_mls_plaintext_bytes (bytes): Serialized MLS Plaintext proposal.
        sender_leaf_index (int): Leaf index of the sender.
        sender_type (int): 1 = MEMBER, 2 = EXTERNAL. Defaults to 1.
    """
    from rfc9420.interop.wire import decode_handshake
    from rfc9420.messages.data_structures import RemoveProposal

    msg = decode_handshake(proposal_mls_plaintext_bytes)
    inner = session._group._inner
    removed_leaf_indices = {
        int(proposal.removed)
        for proposal in getattr(inner, "_pending_proposals", ())
        if isinstance(proposal, RemoveProposal)
    }
    if not removed_leaf_indices:
        session._group.process_proposal(
            msg, sender_leaf_index, sender_type=int(SenderType(sender_type))
        )
        return

    # rfc9420 1.3.0 validates an Add against the current tree before commit
    # creation. Discord commonly sends Remove(old leaf) followed by Add(new key
    # package) for the same user in separate op27 messages. The final tree is
    # valid because commits apply Removes before Adds, but the eager uniqueness
    # check sees the old leaf and rejects the Add. Ignore only leaves already
    # covered by a pending Remove; commit creation still validates the complete
    # resulting tree.
    from unittest.mock import patch

    from rfc9420.group.mls_group import processing as mls_processing
    from rfc9420.mls.exceptions import CommitValidationError

    def validate_with_pending_removals(
        ratchet_tree: Any,
        leaf_node: Any,
        replacing_leaf_index: int | None = None,
    ) -> None:
        if leaf_node is None:
            return
        candidate_signature = getattr(leaf_node, "signature_key", b"")
        candidate_encryption = getattr(leaf_node, "encryption_key", b"")
        for index in range(getattr(ratchet_tree, "n_leaves", 0)):
            if index in removed_leaf_indices or index == replacing_leaf_index:
                continue
            node = ratchet_tree.get_node(index * 2)
            if node is None or node.leaf_node is None:
                continue
            other = node.leaf_node
            if candidate_signature and getattr(other, "signature_key", b"") == candidate_signature:
                raise CommitValidationError(
                    f"duplicate signature_key detected at leaf {index}"
                )
            if candidate_encryption and getattr(other, "encryption_key", b"") == candidate_encryption:
                raise CommitValidationError(
                    f"duplicate encryption_key detected at leaf {index}"
                )

    with _PROPOSAL_VALIDATION_PATCH_LOCK, patch.object(
        mls_processing,
        "validate_leaf_node_unique_against_tree",
        validate_with_pending_removals,
    ):
        session._group.process_proposal(
            msg, sender_leaf_index, sender_type=int(SenderType(sender_type))
        )


def stage_commit_and_welcome(
    session: MLSGroupSession, signing_key_der: bytes
) -> tuple[bytes, list[bytes], Any]:
    """
    Create an outbound commit candidate without changing the active group.

    Discord's voice gateway chooses one client commit and announces it with
    opcode 29. Call :func:`apply_staged_commit` only if that exact candidate is
    selected.
    """
    from rfc9420.interop.wire import encode_handshake

    with _PROPOSAL_VALIDATION_PATCH_LOCK, _rfc9420_dave_commit_interop():
        staged = session._group.create_commit(
            signing_key_der, return_per_joiner_welcomes=True
        )
        # create_commit() marks the live group pending even though its result is
        # only a Discord op28 candidate. Return to the baseline operational
        # state so later op27 messages can add/revoke proposals and produce
        # another candidate for the same epoch.
        from rfc9420.group.mls_group.processing import MlsGroupState

        inner = session._group._inner
        inner._commit_pending = False
        inner._state = MlsGroupState.OPERATIONAL
    commit_bytes = encode_handshake(staged.commit_message)
    welcome_list = [welcome.serialize() for welcome in staged.welcomes]
    return commit_bytes, welcome_list, staged


def apply_staged_commit(session: MLSGroupSession, staged: Any) -> None:
    """Persist and activate a gateway-selected local commit candidate."""
    from rfc9420.api.session import _run_async
    from rfc9420.group.mls_group.processing import MlsGroupState

    _run_async(staged.merge(session._group.config.storage_provider))
    # rfc9420 requires a pending state when activating a locally-created
    # StagedCommit. Candidate staging deliberately released that state.
    session._group._inner._commit_pending = True
    session._group._inner._state = MlsGroupState.PENDING_COMMIT_MEMBER
    session._group.apply_staged_commit(staged)


def create_commit_and_welcome(
    session: MLSGroupSession, signing_key_der: bytes
) -> tuple[bytes, list[bytes]]:
    """
    Create commit and optional welcome messages.

    Used by DaveSession when handle_proposals returns the opcode 28 payload (commit + optional welcome).

    Discord KeyPackages (and RFC 9420 §7.2) leave default types out of
    capabilities. rfc9420 otherwise rejects Adds because the group has the
    required external_senders GroupContext extension. Welcome GroupInfo also
    must not carry GREASE: Discord's gateway drops commits whose Welcome it
    cannot parse.
    """
    commit_bytes, welcome_list, staged = stage_commit_and_welcome(session, signing_key_der)
    apply_staged_commit(session, staged)
    return commit_bytes, welcome_list


def create_remove_proposal_for_self(session: MLSGroupSession, signing_key_der: bytes) -> bytes:
    """
    Create an MLS Remove proposal for the local member (self-remove).

    Optional helper for custom MLS flows. DAVE clients must not send opcode 27
    (gateway-to-client only); the voice gateway issues Remove proposals.

    Args:
        session (MLSGroupSession): MLS group session.
        signing_key_der (bytes): Signing private key (DER) for the member.

    Returns:
        bytes: Serialized MLS Plaintext proposal.
    """
    return session.remove_member(session.own_leaf_index, signing_key_der)


def create_update_proposal(
    session: MLSGroupSession,
    signing_key_der: bytes,
    user_id: int,
    crypto: Union[DefaultCryptoProvider, None] = None,
) -> bytes:
    """
    Create an MLS Update proposal to refresh the local member's leaf node keys.

    Args:
        session (MLSGroupSession): MLS group session.
        signing_key_der (bytes): Signing private key (DER) for the member.
        user_id (int): User ID for credential (64-bit).
        crypto (Union[DefaultCryptoProvider, None]): Crypto provider; uses get_dave_crypto_provider() if None.

    Returns:
        bytes: Serialized MLS Plaintext proposal.

    Raises:
        ValueError: If MLS ciphersuite is unknown.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()
    from rfc9420.messages.data_structures import (
        Credential,
        CredentialType,
        Signature,
    )
    from rfc9420.messages.key_packages import LeafNode, LeafNodeSource

    _dave_cipher_suite()
    _, enc_public = crypto.generate_key_pair()
    sig_private_der, sig_public_bytes = _p256_signing_keypair()
    identity = user_id.to_bytes(8, "big")
    credential = Credential(
        identity=identity,
        public_key=sig_public_bytes,
        credential_type=CredentialType.BASIC,
    )
    capabilities = _dave_capabilities()
    group_id = session.group_id
    leaf_index = session.own_leaf_index
    leaf_node = LeafNode(
        encryption_key=enc_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.UPDATE,
        parent_hash=b"",
        extensions=[],
        signature=Signature(b""),
    )
    leaf_tbs = leaf_node.tbs_serialize(group_id=group_id, leaf_index=leaf_index)
    leaf_sig = crypto.sign_with_label(sig_private_der, _LEAF_NODE_TBS_LABEL, leaf_tbs)
    leaf_node = LeafNode(
        encryption_key=enc_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.UPDATE,
        parent_hash=b"",
        extensions=[],
        signature=Signature(leaf_sig),
    )
    return session.update_self(leaf_node, signing_key_der)
