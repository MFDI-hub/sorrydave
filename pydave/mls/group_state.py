"""
MLS group state manager: rfc9420 integration for DAVE.
Creates group, key package, processes commit/welcome, exports sender base secret.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydave.exceptions import InvalidCommitError

if TYPE_CHECKING:
    from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider
    from rfc9420.mls.group import Group

# DAVE protocol v1: MLS ciphersuite 2 (DHKEMP256_AES128GCM_SHA256_P256)
DAVE_MLS_CIPHERSUITE_ID = 2
EXPORTER_LABEL = b"Discord Secure Frames v0"
EXPORTER_LENGTH = 16


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
    crypto: DefaultCryptoProvider | None = None,
) -> tuple[bytes, bytes, bytes]:
    """
    Create a KeyPackage for the given user_id (64-bit e.g. Discord snowflake).

    Identity is big-endian user_id (8 bytes). Lifetime not_before=0, not_after=2^64-1.

    Args:
        user_id (int): User identifier (64-bit).
        crypto (DefaultCryptoProvider | None): Crypto provider; uses get_dave_crypto_provider() if None.

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


def create_group(
    group_id: bytes,
    key_package_bytes: bytes,
    crypto: DefaultCryptoProvider | None = None,
) -> Group:
    """
    Create a new MLS group with the given key package (single member).

    Args:
        group_id (bytes): Group identifier.
        key_package_bytes (bytes): Serialized KeyPackage of the initial member.
        crypto (DefaultCryptoProvider | None): Crypto provider; uses get_dave_crypto_provider() if None.

    Returns:
        Group: rfc9420 Group instance.
    """
    if crypto is None:
        crypto = get_dave_crypto_provider()
    from rfc9420.mls.group import Group
    from rfc9420.protocol.key_packages import KeyPackage

    kp = KeyPackage.deserialize(key_package_bytes)
    return Group.create(group_id, kp, crypto)


def join_from_welcome(
    welcome_bytes: bytes,
    hpke_private_key: bytes,
    crypto: DefaultCryptoProvider | None = None,
) -> Group:
    """
    Join group from Welcome message.

    Args:
        welcome_bytes (bytes): Serialized MLS Welcome message.
        hpke_private_key (bytes): HPKE private key from the KeyPackage used in the Add.
        crypto (DefaultCryptoProvider | None): Crypto provider; uses get_dave_crypto_provider() if None.

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


def apply_commit(group: Group, commit_mls_plaintext_bytes: bytes, sender_leaf_index: int) -> None:
    """
    Apply a received commit to the group.

    Args:
        group (Group): rfc9420 Group instance.
        commit_mls_plaintext_bytes (bytes): Serialized MLS Plaintext commit message.
        sender_leaf_index (int): Leaf index of the commit sender.

    Raises:
        InvalidCommitError: If commit application fails.
    """
    try:
        from rfc9420.protocol.data_structures import Sender, SenderType
        from rfc9420.protocol.messages import MLSPlaintext

        msg = MLSPlaintext.deserialize(commit_mls_plaintext_bytes)
        sender = Sender(sender_leaf_index, SenderType.MEMBER)
        group.apply_commit(msg, sender.sender)
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
    crypto: DefaultCryptoProvider | None = None,
) -> bytes:
    """
    Create an MLS Update proposal to refresh the local member's leaf node keys.

    Args:
        group (Group): rfc9420 Group instance.
        signing_key_der (bytes): Signing private key (DER) for the member.
        user_id (int): User ID for credential (64-bit).
        crypto (DefaultCryptoProvider | None): Crypto provider; uses get_dave_crypto_provider() if None.

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
