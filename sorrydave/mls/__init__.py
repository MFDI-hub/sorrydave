"""MLS group state management and Voice Gateway opcode handling (rfc9420 integration).

Re-exports a subset of rfc9420 via sorrydave._rfc9420 (see project src_api.md for canonical API map):
codec.tls (TLSDecodeError, read_varint, read_opaque_varint, write_varint, write_opaque_varint),
mls.group (Group, get_commit_sender_leaf_index), and DefaultCryptoProvider for convenience.
"""

from sorrydave._rfc9420 import (
    DefaultCryptoProvider,
    Group,
    TLSDecodeError,
    get_commit_sender_leaf_index,
    read_opaque_varint,
    read_varint,
    write_opaque_varint,
    write_varint,
)

from sorrydave.mls.group_state import (
    apply_commit,
    create_commit_and_welcome,
    create_group,
    create_key_package,
    create_remove_proposal_for_self,
    create_update_proposal,
    export_sender_base_secret,
    get_dave_crypto_provider,
    join_from_welcome,
    process_proposal,
)
from sorrydave.mls.opcodes import (
    build_commit_welcome,
    build_identify,
    build_invalid_commit_welcome,
    build_key_package_message,
    build_ready_for_transition,
    parse_announce_commit,
    parse_client_disconnect,
    parse_clients_connect,
    parse_execute_transition,
    parse_external_sender_package,
    parse_prepare_epoch,
    parse_prepare_transition,
    parse_proposals,
    parse_select_protocol_ack,
    parse_welcome_message,
)

__all__ = [
    "DefaultCryptoProvider",
    "Group",
    "TLSDecodeError",
    "get_commit_sender_leaf_index",
    "read_opaque_varint",
    "read_varint",
    "write_opaque_varint",
    "write_varint",
    "apply_commit",
    "build_commit_welcome",
    "build_identify",
    "build_invalid_commit_welcome",
    "build_key_package_message",
    "build_ready_for_transition",
    "create_commit_and_welcome",
    "create_group",
    "create_key_package",
    "create_remove_proposal_for_self",
    "create_update_proposal",
    "export_sender_base_secret",
    "get_dave_crypto_provider",
    "join_from_welcome",
    "parse_announce_commit",
    "parse_client_disconnect",
    "parse_clients_connect",
    "parse_execute_transition",
    "parse_external_sender_package",
    "parse_prepare_epoch",
    "parse_prepare_transition",
    "parse_proposals",
    "parse_select_protocol_ack",
    "parse_welcome_message",
    "process_proposal",
]
