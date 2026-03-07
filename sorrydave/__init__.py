"""
sorrydave: DAVE (Discord Audio/Video End-to-End Encryption) protocol library.

Pure data-transformation and state-management layer on top of rfc9420 (PyMLS).
No I/O or networking; consume/produce bytes for media and MLS payloads.
"""

from sorrydave.exceptions import DaveProtocolError, DecryptionError, InvalidCommitError
from sorrydave.identity import displayable_code, generate_fingerprint
from sorrydave.media.transform import FrameDecryptor, FrameEncryptor
from sorrydave.session import DaveSession
from sorrydave.types import (
    DaveConfiguration,
    IdentityConfig,
    ProtocolSupplementalData,
    UnencryptedRange,
)

__all__ = [
    "DaveProtocolError",
    "DecryptionError",
    "InvalidCommitError",
    "UnencryptedRange",
    "ProtocolSupplementalData",
    "DaveConfiguration",
    "IdentityConfig",
    "DaveSession",
    "FrameEncryptor",
    "FrameDecryptor",
    "generate_fingerprint",
    "displayable_code",
]

__version__ = "0.1.0"
