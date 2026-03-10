"""
sorrydave: DAVE (Discord Audio/Video End-to-End Encryption) protocol library.

Pure data-transformation and state-management layer on top of rfc9420 (PyMLS).
No I/O or networking; consume/produce bytes for media and MLS payloads.
"""

from sorrydave.exceptions import DaveProtocolError, DecryptionError, InvalidCommitError
from sorrydave.identity import displayable_code, generate_fingerprint
from sorrydave.media.transform import FrameDecryptor, FrameEncryptor
from sorrydave.persistent_keys import (
    VoicePublicKeysPayload,
    build_voice_public_keys_upload_payload,
    generate_p256_keypair,
    load_persistent_signature_key,
    save_persistent_signature_key,
)
from sorrydave.session import DaveSession, SharedIdentityContext
from sorrydave.types import (
    DaveConfiguration,
    IdentityConfig,
    ProtocolSupplementalData,
    UnencryptedRange,
)
from sorrydave.verification import VerificationStore, VerifiedIdentity
from sorrydave._rfc9420 import DefaultCryptoProvider, Group, SenderType, TLSDecodeError

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
    "FrameEncryptor",
    "FrameDecryptor",
    "generate_fingerprint",
    "displayable_code",
    "VoicePublicKeysPayload",
    "build_voice_public_keys_upload_payload",
    "generate_p256_keypair",
    "load_persistent_signature_key",
    "save_persistent_signature_key",
    "VerifiedIdentity",
    "VerificationStore",
]

__version__ = "0.6.0"
