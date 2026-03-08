"""
MLS group state manager: rfc9420 integration for DAVE.
Creates group, key package, processes commit/welcome, exports sender base secret.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Union

from sorrydave.exceptions import InvalidCommitError

if TYPE_CHECKING:
    from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider
    from rfc9420.mls.group import Group

# DAVE protocol v1: MLS ciphersuite 2 (DHKEMP256_AES128GCM_SHA256_P256)
DAVE_MLS_CIPHERSUITE_ID = 2
EXPORTER_LABEL = b"Discord Secure Frames v0"
EXPORTER_LENGTH = 16
EXTENSION_TYPE_EXTERNAL_SENDERS = 0x0002


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

    Returns:
        DefaultCryptoProvider: Instance for DHKEMP256_AES128GCM_SHA256_P256.
    """
    from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider

    return DefaultCryptoProvider(suite_id=DAVE_MLS_CIPHERSUITE_ID)


def create_key_package(
    user_id: int,
    crypto: Union[DefaultCryptoProvider, None] = None,
) -> tuple[bytes, bytes, bytes]:
    """
    Create a KeyPackage for the given user_id (64-bit e.g. Discord snowflake).

    Identity is big-endian user_id (8 bytes). Lifetime not_before=0, not_after=2^64-1.

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

    from rfc9420.crypto.ciphersuites import get_ciphersuite_by_id
    from rfc9420.protocol.data_structures import (
        CipherSuite,
        Credential,
        CredentialType,
        MLSVersion,
        Signature,
    )
    from rfc9420.protocol.key_packages import KeyPackage, LeafNode, LeafNodeSource

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
    Returns the raw bytes for the GroupContext.extensions field (inner content
    of Extension extensions<V>, without the outer vector length prefix).
    Wire format per RFC 9420 section 12.1.8.1:
        Extension { uint16 extension_type; opaque extension_data<V>; }
        ExternalSendersExtension { ExternalSender external_senders<V>; }
        ExternalSender { SignaturePublicKey signature_key; Credential credential; }
        Credential { uint16 credential_type; opaque identity<V>; }
    """
    ext_sender = _write_opaque_varint(signature_key)
    ext_sender += struct.pack("!H", credential_type)
    ext_sender += _write_opaque_varint(identity)
    ext_senders_list = _write_opaque_varint(ext_sender)
    extension = struct.pack("!H", EXTENSION_TYPE_EXTERNAL_SENDERS)
    extension += _write_opaque_varint(ext_senders_list)
    return extension


def get_external_senders_from_group(group: Group) -> list[tuple[bytes, int, bytes]]:
    """
    Parse GroupContext.extensions and return list of (signature_key, credential_type, identity)
    for the external_senders extension (type 0x0002).

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
        n_ext, pos = _read_varint(data, 0)
        result: list[tuple[bytes, int, bytes]] = []
        for _ in range(n_ext):
            if pos + 2 > len(data):
                break
            ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
            pos += 2
            ext_data, pos = _read_opaque_varint(data, pos)
            if ext_type != EXTENSION_TYPE_EXTERNAL_SENDERS:
                continue
            ext_senders_list, off = _read_opaque_varint(ext_data, 0)
            if off != len(ext_data):
                continue
            while off < len(ext_senders_list):
                sig_key, off = _read_opaque_varint(ext_senders_list, off)
                if off + 2 > len(ext_senders_list):
                    break
                cred_type = struct.unpack("!H", ext_senders_list[off : off + 2])[0]
                off += 2
                identity, off = _read_opaque_varint(ext_senders_list, off)
                result.append((sig_key, cred_type, identity))
        return result
    except Exception:
        return []


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


def _inject_group_extensions(group: Group, extensions_bytes: bytes) -> None:
    """Replace the GroupContext extensions on an epoch-0 group.
    At epoch 0, KeySchedule.from_epoch_secret does not bind the group context
    into the key derivation (only the random epoch secret is used), so swapping
    the GroupContext with updated extensions is safe before any commits.
    """
    from rfc9420.protocol.data_structures import GroupContext

    inner = group._inner
    old_gc = inner._group_context
    if old_gc is None:
        return
    new_gc = GroupContext(
        group_id=old_gc.group_id,
        epoch=old_gc.epoch,
        tree_hash=old_gc.tree_hash,
        confirmed_transcript_hash=old_gc.confirmed_transcript_hash,
        extensions=extensions_bytes,
        version=old_gc.version,
        cipher_suite_id=old_gc.cipher_suite_id,
    )
    inner._group_context = new_gc
    if inner._key_schedule is not None:
        inner._key_schedule._group_context = new_gc


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

    When external sender parameters are provided, the group extensions will
    include the required external_senders extension (type 0x0002) per RFC 9420
    section 12.1.8.1.  This is mandatory for the DAVE protocol.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()
    from rfc9420.mls.group import Group
    from rfc9420.protocol.key_packages import KeyPackage

    kp = KeyPackage.deserialize(key_package_bytes)
    group = Group.create(group_id, kp, crypto)

    if external_sender_signature_key is not None and external_sender_identity is not None:
        extensions_bytes = serialize_external_senders_extension(
            signature_key=external_sender_signature_key,
            credential_type=external_sender_credential_type,
            identity=external_sender_identity,
        )
        _inject_group_extensions(group, extensions_bytes)

    return group


def join_from_welcome(
    welcome_bytes: bytes,
    hpke_private_key: bytes,
    crypto: Union[DefaultCryptoProvider, None] = None,
) -> Group:
    """
    Join group from Welcome message.

    Args:
        welcome_bytes (bytes): Serialized MLS Welcome message.
        hpke_private_key (bytes): HPKE private key from the KeyPackage used in the Add.
        crypto (Union[DefaultCryptoProvider, None]): Crypto provider; uses get_dave_crypto_provider() if None.

    Returns:
        Group: rfc9420 Group instance.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()
    from rfc9420.mls.group import Group
    from rfc9420.protocol.data_structures import Welcome

    welcome = Welcome.deserialize(welcome_bytes)
    return Group.join_from_welcome(welcome, hpke_private_key, crypto)


def export_sender_base_secret(group: Group, sender_user_id: int) -> bytes:
    """
    Export 16-byte sender base secret via MLS Exporter.

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
    inner = group._inner
    tree = getattr(inner, "_ratchet_tree", None)
    if tree is None:
        return
    seen: set[bytes] = set()
    n = inner.get_member_count()
    for leaf_index in range(n):
        try:
            node = tree.get_node(leaf_index * 2)
            if node is None or not getattr(node, "leaf_node", None):
                continue
            leaf = node.leaf_node
            cred = getattr(leaf, "credential", None)
            if cred is None:
                continue
            identity = getattr(cred, "identity", None)
            if identity is None or len(identity) < 8:
                continue
            id_bytes = identity[:8]
            if id_bytes in seen:
                raise InvalidCommitError("Duplicate basic credential in group tree")
            seen.add(id_bytes)
        except InvalidCommitError:
            raise
        except Exception:
            continue


def apply_commit(group: Group, commit_mls_plaintext_bytes: bytes, sender_leaf_index: int) -> None:
    """
    Apply a received commit to the group.

    Per DAVE client commit validity, raises InvalidCommitError if the resulting
    group would have duplicate basic credentials (user IDs).

    Args:
        group (Group): rfc9420 Group instance.
        commit_mls_plaintext_bytes (bytes): Serialized MLS Plaintext commit message.
        sender_leaf_index (int): Leaf index of the commit sender.

    Raises:
        InvalidCommitError: If commit application fails or duplicate credentials.
    """
    try:
        from rfc9420.protocol.data_structures import Sender, SenderType
        from rfc9420.protocol.messages import MLSPlaintext

        msg = MLSPlaintext.deserialize(commit_mls_plaintext_bytes)
        sender = Sender(sender_leaf_index, SenderType.MEMBER)
        group.apply_commit(msg, sender.sender)
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

    Args:
        group (Group): rfc9420 Group instance.
        proposal_mls_plaintext_bytes (bytes): Serialized MLS Plaintext proposal.
        sender_leaf_index (int): Leaf index of the sender.
        sender_type (int): 1 = MEMBER, 2 = EXTERNAL. Defaults to 1.
    """
    from rfc9420.protocol.data_structures import Sender, SenderType
    from rfc9420.protocol.messages import MLSPlaintext

    msg = MLSPlaintext.deserialize(proposal_mls_plaintext_bytes)
    st = SenderType.EXTERNAL if sender_type == 2 else SenderType.MEMBER
    group._inner.process_proposal(msg, Sender(sender_leaf_index, st))


def create_commit_and_welcome(group: Group, signing_key_der: bytes) -> tuple[bytes, list[bytes]]:
    """
    Create commit and optional welcome messages.

    Args:
        group (Group): rfc9420 Group instance with pending proposals.
        signing_key_der (bytes): Signing private key (DER) for the committing member.

    Returns:
        tuple[bytes, list[bytes]]: (serialized commit plaintext, list of serialized Welcome bytes).
    """

    commit_plaintext, welcomes = group.commit(signing_key_der)
    commit_bytes: bytes = commit_plaintext.serialize()
    welcome_list: list[bytes] = [w.serialize() for w in welcomes]
    return (commit_bytes, welcome_list)


def create_remove_proposal_for_self(group: Group, signing_key_der: bytes) -> bytes:
    """
    Create an MLS Remove proposal for the local member (self-remove).

    Args:
        group (Group): rfc9420 Group instance.
        signing_key_der (bytes): Signing private key (DER) for the member.

    Returns:
        bytes: Serialized MLS Plaintext proposal to send (e.g. via opcode 27).
    """
    own_leaf_index = group._inner._own_leaf_index
    proposal = group.remove(own_leaf_index, signing_key_der)
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
    from rfc9420.crypto.ciphersuites import get_ciphersuite_by_id
    from rfc9420.protocol.data_structures import (
        Credential,
        CredentialType,
        Signature,
    )
    from rfc9420.protocol.key_packages import LeafNode, LeafNodeSource

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
    leaf_index = group._inner._own_leaf_index
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
