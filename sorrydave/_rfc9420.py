"""
Internal bridge to rfc9420 (PyMLS). Single source of rfc9420 imports for sorrydave.

All symbols are imported from rfc9420 using only the module paths and names
defined in the project's src_api.md (canonical API map). No other sorrydave
module should import from rfc9420 directly.
"""

from rfc9420.codec.tls import (
    TLSDecodeError,
    read_opaque_varint,
    read_varint,
    write_opaque_varint,
    write_varint,
)
from rfc9420.crypto.ciphersuites import get_ciphersuite_by_id
from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider
from rfc9420.extensions.extensions import parse_external_senders
from rfc9420.mls.group import Group, get_commit_sender_leaf_index
from rfc9420.protocol.data_structures import (
    AddProposal,
    CipherSuite,
    Commit,
    Credential,
    CredentialType,
    MLSVersion,
    Proposal,
    ProposalOrRefType,
    ProposalType,
    SenderType,
    Signature,
    Welcome,
)
from rfc9420.protocol.key_packages import KeyPackage, LeafNode, LeafNodeSource
from rfc9420.protocol.messages import ContentType, MLSPlaintext

__all__ = [
    "AddProposal",
    "CipherSuite",
    "Commit",
    "ContentType",
    "Credential",
    "CredentialType",
    "DefaultCryptoProvider",
    "Group",
    "KeyPackage",
    "LeafNode",
    "LeafNodeSource",
    "MLSPlaintext",
    "MLSVersion",
    "Proposal",
    "ProposalOrRefType",
    "ProposalType",
    "SenderType",
    "Signature",
    "TLSDecodeError",
    "Welcome",
    "get_ciphersuite_by_id",
    "get_commit_sender_leaf_index",
    "parse_external_senders",
    "read_opaque_varint",
    "read_varint",
    "write_opaque_varint",
    "write_varint",
]
