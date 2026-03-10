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
    create_remove_proposal_for_self: Remove proposal for local member; used by DaveSession.leave_group.
    create_update_proposal: Update proposal to refresh leaf keys; optional.
    validate_group_dave_ciphersuite_and_extensions: Check ciphersuite and extension list for DAVE.
    validate_group_external_sender: Check external sender matches; used when applying commits.
    get_external_senders_from_group: Read external senders from group context.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Union

from sorrydave.exceptions import InvalidCommitError

if TYPE_CHECKING:
    from sorrydave._rfc9420 import DefaultCryptoProvider, Group

# DAVE protocol v1: MLS ciphersuite 2 (DHKEMP256_AES128GCM_SHA256_P256)
DAVE_MLS_CIPHERSUITE_ID = 2
EXPORTER_LABEL = b"Discord Secure Frames v0"
EXPORTER_LENGTH = 16
EXTENSION_TYPE_EXTERNAL_SENDERS = 0x0002


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read MLS-style varint from data at offset; delegates to sorrydave._rfc9420 (rfc9420.codec.tls)."""
    from sorrydave._rfc9420 import read_varint

    return read_varint(data, offset)


def _read_opaque_varint(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read opaque<V>: varint length then that many bytes; delegates to sorrydave._rfc9420 (rfc9420.codec.tls)."""
    from sorrydave._rfc9420 import read_opaque_varint

    return read_opaque_varint(data, offset)


def get_dave_crypto_provider() -> DefaultCryptoProvider:
    """
    Return rfc9420 DefaultCryptoProvider with DAVE MLS ciphersuite (2).

    Used by DaveSession when creating key packages and groups.

    Returns:
        DefaultCryptoProvider: Instance for DHKEMP256_AES128GCM_SHA256_P256.
    """
    from sorrydave._rfc9420 import DefaultCryptoProvider

    return DefaultCryptoProvider(suite_id=DAVE_MLS_CIPHERSUITE_ID)


def create_key_package(
    user_id: int,
    crypto: Union[DefaultCryptoProvider, None] = None,
) -> tuple[bytes, bytes, bytes]:
    """
    Create a KeyPackage for the given user_id (64-bit e.g. Discord snowflake).

    Used by DaveSession when prepare_epoch(1) is called. Identity is big-endian user_id (8 bytes).
    Lifetime not_before=0, not_after=2^64-1.

    Args:
        user_id (int): User identifier (64-bit).
        crypto (Union[DefaultCryptoProvider, None]): Crypto provider; uses get_dave_crypto_provider() if None.

    Returns:
        tuple[bytes, bytes, bytes]: (key_package_serialized, hpke_private_key, signing_key_der).

    Raises:
        ValueError: If MLS ciphersuite is unknown.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()

    from sorrydave._rfc9420 import (
        CipherSuite,
        Credential,
        CredentialType,
        KeyPackage,
        LeafNode,
        LeafNodeSource,
        MLSVersion,
        Signature,
        get_ciphersuite_by_id,
    )

    cs = get_ciphersuite_by_id(DAVE_MLS_CIPHERSUITE_ID)
    if cs is None:
        raise ValueError(f"Unknown MLS ciphersuite id {DAVE_MLS_CIPHERSUITE_ID}")
    cipher_suite = CipherSuite(cs.kem, cs.kdf, cs.aead, suite_id=cs.suite_id)
    # Generate HPKE key pair (for init_key and leaf encryption_key)
    hpke_private, hpke_public = crypto.generate_key_pair()
    # Generate ECDSA P256 signing key pair for leaf
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
    identity = user_id.to_bytes(8, "big")
    credential = Credential(
        identity=identity,
        public_key=sig_public_bytes,
        credential_type=CredentialType.BASIC,
    )
    capabilities = b""  # minimal; extensions can be empty list
    lifetime_not_before = 0
    lifetime_not_after = (1 << 64) - 1
    leaf_node = LeafNode(
        encryption_key=hpke_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.KEY_PACKAGE,
        lifetime_not_before=lifetime_not_before,
        lifetime_not_after=lifetime_not_after,
        extensions=[],
        signature=b"",
    )
    leaf_tbs = leaf_node.tbs_serialize()
    leaf_sig = crypto.sign(sig_private_der, leaf_tbs)
    leaf_node = LeafNode(
        encryption_key=hpke_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.KEY_PACKAGE,
        lifetime_not_before=lifetime_not_before,
        lifetime_not_after=lifetime_not_after,
        extensions=[],
        signature=Signature(leaf_sig),
    )
    init_key = hpke_public  # DAVE uses same as leaf encryption key per typical MLS
    kp = KeyPackage(
        version=MLSVersion.MLS10,
        cipher_suite=cipher_suite,
        init_key=init_key,
        leaf_node=leaf_node,
        extensions=[],
        signature=Signature(b""),
    )
    kp_tbs = kp.tbs_serialize()
    kp_sig = crypto.sign(sig_private_der, kp_tbs)
    kp = KeyPackage(
        version=MLSVersion.MLS10,
        cipher_suite=cipher_suite,
        init_key=init_key,
        leaf_node=leaf_node,
        extensions=[],
        signature=Signature(kp_sig),
    )
    return (kp.serialize(), hpke_private, sig_private_der)


def _write_varint(x: int) -> bytes:
    """RFC 9420 variable-length integer encoding; delegates to sorrydave._rfc9420 (rfc9420.codec.tls)."""
    from sorrydave._rfc9420 import write_varint

    return write_varint(x)


def _write_opaque_varint(data: bytes) -> bytes:
    """Encode opaque<V>: varint length prefix + data; delegates to sorrydave._rfc9420 (rfc9420.codec.tls)."""
    from sorrydave._rfc9420 import write_opaque_varint

    return write_opaque_varint(data)


def serialize_external_senders_extension(
    signature_key: bytes,
    credential_type: int,
    identity: bytes,
) -> bytes:
    """Serialize the external_senders group extension for the MLS GroupContext.
    Returns the raw bytes for the GroupContext.extensions field (inner content
    of Extension extensions<V>, without the outer vector length prefix).
    Wire format per RFC 9420 section 12.1.8.1:
        Extension { uint16 extension_type; opaque extension_data<V>; }
        ExternalSendersExtension { ExternalSender external_senders<V>; }
        ExternalSender { SignaturePublicKey signature_key; Credential credential; }
        Credential { uint16 credential_type; opaque identity<V>; }
    """
    from sorrydave._rfc9420 import write_opaque_varint

    ext_sender = write_opaque_varint(signature_key)
    ext_sender += struct.pack("!H", credential_type)
    ext_sender += write_opaque_varint(identity)
    ext_senders_list = write_opaque_varint(ext_sender)
    extension = struct.pack("!H", EXTENSION_TYPE_EXTERNAL_SENDERS)
    extension += write_opaque_varint(ext_senders_list)
    return extension


def get_external_senders_from_group(group: Group) -> list[tuple[bytes, int, bytes]]:
    """
    Parse GroupContext.extensions and return list of (signature_key, credential_type, identity)
    for the external_senders extension (type 0x0002).

    Note: Uses ``group._inner._group_context`` because the rfc9420 Group public API
    does not expose group context extensions.  This is the only _inner access retained
    and is required for protocol-mandated external sender validation (protocol.md
    §Invalid Groups).

    Returns:
        list[tuple[bytes, int, bytes]]: Empty if no external senders extension or parse error.
    """
    try:
        inner = group._inner
        gc = inner._group_context
        if gc is None or not gc.extensions:
            return []
    except Exception:
        return []
    data = gc.extensions if isinstance(gc.extensions, bytes) else b""
    if not data:
        return []
    try:
        from sorrydave._rfc9420 import parse_external_senders, read_opaque_varint

        n_ext, pos = _read_varint(data, 0)
        result: list[tuple[bytes, int, bytes]] = []
        for _ in range(n_ext):
            if pos + 2 > len(data):
                break
            ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2
            ext_data, pos = read_opaque_varint(data, pos)
            if ext_type != EXTENSION_TYPE_EXTERNAL_SENDERS:
                continue
            try:
                senders = parse_external_senders(ext_data)
            except Exception:
                continue
            for es in senders:
                if len(es.credential_data) < 2:
                    continue
                cred_type = struct.unpack("!H", es.credential_data[:2])[0]
                try:
                    identity, _ = read_opaque_varint(es.credential_data, 2)
                except Exception:
                    continue
                result.append((es.signature_key, cred_type, identity))
        return result
    except Exception:
        return []


def validate_group_dave_ciphersuite_and_extensions(group: Group) -> None:
    """
    Verify the group has the expected DAVE ciphersuite and extension list (protocol version).

    Per protocol: group must have expected ciphersuite and extension list (external_senders only).

    Raises:
        InvalidCommitError: If ciphersuite is not DAVE or extensions are not exactly external_senders.
    """
    try:
        inner = group._inner
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
        n_ext, pos = _read_varint(data, 0)
        if n_ext != 1:
            raise InvalidCommitError(
                f"Group must have exactly one extension (external_senders); got {n_ext}"
            )
        if pos + 2 > len(data):
            raise InvalidCommitError("Group extensions truncated")
        ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2
        if ext_type != EXTENSION_TYPE_EXTERNAL_SENDERS:
            raise InvalidCommitError(
                f"Group extension must be external_senders (0x0002); got 0x{ext_type:04x}"
            )
        from sorrydave._rfc9420 import read_opaque_varint

        ext_data, pos = read_opaque_varint(data, pos)
        if pos != len(data):
            raise InvalidCommitError("Group extensions truncated")
    except InvalidCommitError:
        raise
    except Exception as e:
        raise InvalidCommitError("Invalid group ciphersuite or extensions") from e


def validate_group_external_sender(
    group: Group,
    expected_signature_key: bytes,
    expected_credential_type: int,
    expected_identity: bytes,
) -> None:
    """
    Verify the group has exactly one external sender matching the voice gateway package.

    Raises:
        InvalidCommitError: If not exactly one external sender or no match.
    """
    senders = get_external_senders_from_group(group)
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
) -> Group:
    """
    Create a new MLS group with the given key package (single member).

    Used by DaveSession when handle_external_sender_package is called and a key package
    was already prepared. When external sender parameters are provided, the group
    extensions include the required external_senders extension (type 0x0002) per
    RFC 9420 section 12.1.8.1. This is mandatory for the DAVE protocol.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()
    from sorrydave._rfc9420 import Group, KeyPackage

    initial_extensions = b""
    if external_sender_signature_key is not None and external_sender_identity is not None:
        initial_extensions = serialize_external_senders_extension(
            signature_key=external_sender_signature_key,
            credential_type=external_sender_credential_type,
            identity=external_sender_identity,
        )

    kp = KeyPackage.deserialize(key_package_bytes)
    group = Group.create(group_id, kp, crypto, initial_extensions=initial_extensions)
    if external_sender_signature_key is not None and hasattr(group, "set_external_sender_keys"):
        group.set_external_sender_keys([external_sender_signature_key])
    return group


def join_from_welcome(
    welcome_bytes: bytes,
    hpke_private_key: bytes,
    crypto: Union[DefaultCryptoProvider, None] = None,
) -> Group:
    """
    Join group from Welcome message.

    Used by DaveSession when handle_welcome is called (client was added to the group).

    Args:
        welcome_bytes (bytes): Serialized MLS Welcome message.
        hpke_private_key (bytes): HPKE private key from the KeyPackage used in the Add.
        crypto (Union[DefaultCryptoProvider, None]): Crypto provider; uses get_dave_crypto_provider() if None.

    Returns:
        Group: rfc9420 Group instance.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()
    from sorrydave._rfc9420 import Group, Welcome

    welcome = Welcome.deserialize(welcome_bytes)
    return Group.join_from_welcome(welcome, hpke_private_key, crypto)


def export_sender_base_secret(group: Group, sender_user_id: int) -> bytes:
    """
    Export 16-byte sender base secret via MLS Exporter.

    Used by DaveSession when refreshing send/receive ratchets (KeyRatchet base secret).
    Uses label "Discord Secure Frames v0" and context = little-endian 64-bit sender user ID.

    Args:
        group (Group): rfc9420 Group instance.
        sender_user_id (int): Sender user ID (64-bit).

    Returns:
        bytes: 16-byte base secret for KeyRatchet.
    """
    context = sender_user_id.to_bytes(8, "little")
    result: bytes = group.export_secret(EXPORTER_LABEL, context, EXPORTER_LENGTH)
    return result


def _check_no_duplicate_credentials(group: Group) -> None:
    """
    Raise InvalidCommitError if the group tree has duplicate basic credentials (user IDs).

    Per DAVE client commit validity: "The resulting group includes a duplicated basic
    credential (i.e. the big-endian user ID snowflake) between two or more leaf nodes."
    """
    seen: set[bytes] = set()
    try:
        for _leaf_index, identity in group.iter_members():
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


def _validate_commit_proposal_refs_only(commit_mls_plaintext_bytes: bytes) -> None:
    """
    Client Commit Validity (protocol.md): refuse commits that include inline proposals.

    DAVE requires all included proposals to be proposal references (not inline).
    Raises InvalidCommitError if any proposal in the commit is inline.
    """
    from sorrydave._rfc9420 import Commit, ContentType, MLSPlaintext, ProposalOrRefType

    msg = MLSPlaintext.deserialize(commit_mls_plaintext_bytes)
    content = msg.auth_content.tbs.framed_content
    if content.content_type != ContentType.COMMIT:
        return
    commit = Commit.deserialize(content.content)
    for prop in commit.proposals:
        if prop.typ == ProposalOrRefType.PROPOSAL:
            raise InvalidCommitError(
                "DAVE requires all commit proposals to be proposal references (no inline proposals)"
            )


def apply_commit(
    group: Group,
    commit_mls_plaintext_bytes: bytes,
    sender_leaf_index: Union[int, None] = None,
) -> None:
    """
    Apply a received commit to the group.

    Used by DaveSession when handle_commit is called. Per protocol.md Client Commit Validity:
    - All included proposals must be proposal references (no inline proposals).
    - The resulting group must not have duplicate basic credentials (user IDs).
    Raises InvalidCommitError if either check fails or if commit application fails.

    Args:
        group (Group): rfc9420 Group instance.
        commit_mls_plaintext_bytes (bytes): Serialized MLS Plaintext commit message.
        sender_leaf_index (Union[int, None]): Leaf index of the commit sender; if None,
            obtained via rfc9420.get_commit_sender_leaf_index(commit_mls_plaintext_bytes).

    Raises:
        InvalidCommitError: If commit application fails or Client Commit Validity is violated.
    """
    try:
        from sorrydave._rfc9420 import get_commit_sender_leaf_index, MLSPlaintext

        _validate_commit_proposal_refs_only(commit_mls_plaintext_bytes)
        if sender_leaf_index is None:
            sender_leaf_index = get_commit_sender_leaf_index(commit_mls_plaintext_bytes)
        msg = MLSPlaintext.deserialize(commit_mls_plaintext_bytes)
        group.apply_commit(msg, sender_leaf_index)
        _check_no_duplicate_credentials(group)
    except InvalidCommitError:
        raise
    except Exception as e:
        raise InvalidCommitError("Failed to apply commit") from e


def process_proposal(
    group: Group,
    proposal_mls_plaintext_bytes: bytes,
    sender_leaf_index: int,
    sender_type: int = 1,
) -> None:
    """
    Process a proposal (e.g. Add/Remove from external sender).

    Used by DaveSession when handle_proposals is called to apply each proposal
    before creating a commit.

    Args:
        group (Group): rfc9420 Group instance.
        proposal_mls_plaintext_bytes (bytes): Serialized MLS Plaintext proposal.
        sender_leaf_index (int): Leaf index of the sender.
        sender_type (int): 1 = MEMBER, 2 = EXTERNAL. Defaults to 1.
    """
    from sorrydave._rfc9420 import MLSPlaintext, SenderType

    msg = MLSPlaintext.deserialize(proposal_mls_plaintext_bytes)
    st = SenderType.EXTERNAL if sender_type == 2 else SenderType.MEMBER
    group.process_proposal(msg, sender_leaf_index, sender_type=st)


def create_commit_and_welcome(group: Group, signing_key_der: bytes) -> tuple[bytes, list[bytes]]:
    """
    Create commit and optional welcome messages.

    Used by DaveSession when handle_proposals returns the opcode 28 payload (commit + optional welcome).

    Args:
        group (Group): rfc9420 Group instance with pending proposals.
        signing_key_der (bytes): Signing private key (DER) for the committing member.

    Returns:
        tuple[bytes, list[bytes]]: (serialized commit plaintext, list of serialized Welcome bytes).
    """

    commit_plaintext, welcomes = group.commit(signing_key_der, return_per_joiner_welcomes=True)
    commit_bytes: bytes = commit_plaintext.serialize()
    welcome_list: list[bytes] = [w.serialize() for w in welcomes]
    return (commit_bytes, welcome_list)


def create_remove_proposal_for_self(group: Group, signing_key_der: bytes) -> bytes:
    """
    Create an MLS Remove proposal for the local member (self-remove).

    Used by DaveSession when leave_group is called; return value is sent as opcode 27.

    Args:
        group (Group): rfc9420 Group instance.
        signing_key_der (bytes): Signing private key (DER) for the member.

    Returns:
        bytes: Serialized MLS Plaintext proposal to send (e.g. via opcode 27).
    """
    proposal = group.remove(group.own_leaf_index, signing_key_der)
    return proposal.serialize()


def create_update_proposal(
    group: Group,
    signing_key_der: bytes,
    user_id: int,
    crypto: Union[DefaultCryptoProvider, None] = None,
) -> bytes:
    """
    Create an MLS Update proposal to refresh the local member's leaf node keys.

    Args:
        group (Group): rfc9420 Group instance.
        signing_key_der (bytes): Signing private key (DER) for the member.
        user_id (int): User ID for credential (64-bit).
        crypto (Union[DefaultCryptoProvider, None]): Crypto provider; uses get_dave_crypto_provider() if None.

    Returns:
        bytes: Serialized MLS Plaintext proposal to send (e.g. via opcode 27).

    Raises:
        ValueError: If MLS ciphersuite is unknown.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()
    from sorrydave._rfc9420 import (
        Credential,
        CredentialType,
        LeafNode,
        LeafNodeSource,
        Signature,
        get_ciphersuite_by_id,
    )

    cs = get_ciphersuite_by_id(DAVE_MLS_CIPHERSUITE_ID)
    if cs is None:
        raise ValueError(f"Unknown MLS ciphersuite id {DAVE_MLS_CIPHERSUITE_ID}")
    hpke_private, hpke_public = crypto.generate_key_pair()
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
    identity = user_id.to_bytes(8, "big")
    credential = Credential(
        identity=identity,
        public_key=sig_public_bytes,
        credential_type=CredentialType.BASIC,
    )
    capabilities = b""
    lifetime_not_before = 0
    lifetime_not_after = (1 << 64) - 1
    group_id = group.group_id
    leaf_index = group.own_leaf_index
    leaf_node = LeafNode(
        encryption_key=hpke_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.UPDATE,
        lifetime_not_before=lifetime_not_before,
        lifetime_not_after=lifetime_not_after,
        extensions=[],
        signature=b"",
    )
    leaf_tbs = leaf_node.tbs_serialize(group_id=group_id, leaf_index=leaf_index)
    leaf_sig = crypto.sign(sig_private_der, leaf_tbs)
    leaf_node = LeafNode(
        encryption_key=hpke_public,
        signature_key=sig_public_bytes,
        credential=credential,
        capabilities=capabilities,
        leaf_node_source=LeafNodeSource.UPDATE,
        lifetime_not_before=lifetime_not_before,
        lifetime_not_after=lifetime_not_after,
        extensions=[],
        signature=Signature(leaf_sig),
    )
    proposal = group.update(leaf_node, signing_key_der)
    return proposal.serialize()
