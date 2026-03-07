"""
pydave: DAVE (Discord Audio/Video End-to-End Encryption) protocol library.

Pure data-transformation and state-management layer on top of rfc9420 (PyMLS).
No I/O or networking; consume/produce bytes for media and MLS payloads.
"""

from pydave.exceptions import DaveProtocolError, DecryptionError, InvalidCommitError
from pydave.identity import displayable_code, generate_fingerprint
from pydave.media.transform import FrameDecryptor, FrameEncryptor
from pydave.session import DaveSession
from pydave.types import (
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
