"""
sorrydave: DAVE (Discord Audio/Video End-to-End Encryption) protocol library.

Pure data-transformation and state-management layer on top of rfc9420 (PyMLS).
No I/O or networking; consume/produce bytes for media and MLS payloads.
"""

from rfc9420 import (
    DefaultCryptoProvider,
    SenderType,
    TLSDecodeError,
)
from rfc9420 import (
    MLSGroup as Group,
)

from sorrydave.exceptions import DaveProtocolError, DecryptionError, InvalidCommitError
from sorrydave.identity import displayable_code, generate_fingerprint
from sorrydave.media.transform import (
    SILENCE_PACKET,
    FrameDecryptor,
    FrameEncryptor,
    protocol_frame_check,
)
from sorrydave.persistent_keys import (
    VoicePublicKeysPayload,
    build_match_public_key_payload,
    build_voice_public_keys_upload_payload,
    generate_p256_keypair,
    load_persistent_signature_key,
    save_persistent_signature_key,
)
from sorrydave.session import (
    PREPARE_DEFER_UNTIL_MEDIA_READY,
    PREPARE_EXECUTE_NOW,
    PREPARE_WAIT_FOR_EXECUTE,
    DaveSession,
    SharedIdentityContext,
    mls_channel_id_from_stream_server_id,
    mls_group_id_from_channel_id,
    mls_group_id_from_stream_server_id,
)
from sorrydave.types import (
    DaveConfiguration,
    IdentityConfig,
    ProtocolSupplementalData,
    UnencryptedRange,
)
from sorrydave.verification import VerificationStore, VerifiedIdentity

__all__ = [
    "DaveProtocolError",
    "DecryptionError",
    "DefaultCryptoProvider",
    "Group",
    "InvalidCommitError",
    "SenderType",
    "TLSDecodeError",
    "UnencryptedRange",
    "ProtocolSupplementalData",
    "DaveConfiguration",
    "IdentityConfig",
    "DaveSession",
    "SharedIdentityContext",
    "mls_group_id_from_channel_id",
    "mls_channel_id_from_stream_server_id",
    "mls_group_id_from_stream_server_id",
    "PREPARE_EXECUTE_NOW",
    "PREPARE_DEFER_UNTIL_MEDIA_READY",
    "PREPARE_WAIT_FOR_EXECUTE",
    "FrameEncryptor",
    "FrameDecryptor",
    "protocol_frame_check",
    "SILENCE_PACKET",
    "generate_fingerprint",
    "displayable_code",
    "VoicePublicKeysPayload",
    "build_voice_public_keys_upload_payload",
    "build_match_public_key_payload",
    "generate_p256_keypair",
    "load_persistent_signature_key",
    "save_persistent_signature_key",
    "VerifiedIdentity",
    "VerificationStore",
]

__version__ = "0.10.6"
