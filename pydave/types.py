"""
DAVE protocol data structures and configuration types.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, slots=True)
class UnencryptedRange:
    """Byte range that must remain plaintext for SFU routing (e.g. codec headers)."""

    offset: int
    length: int


@dataclass(slots=True)
class ProtocolSupplementalData:
    """
    Parsed DAVE protocol footer (supplemental data).
    Layout: 8-byte tag, ULEB128 nonce, ULEB128 offset/length pairs, 1-byte size, 2-byte magic 0xFAFA.
    """

    tag_8: bytes
    nonce_32: int
    unencrypted_ranges: list[UnencryptedRange]
    supplemental_size: int


@dataclass(frozen=True, slots=True)
class DaveConfiguration:
    """Immutable configuration for DAVE protocol version and ciphersuite."""

    protocol_version: int = 1
    mls_ciphersuite: int = 2  # DHKEMP256_AES128GCM_SHA256_P256
    media_ciphersuite: str = "AES128-GCM"
    ratchet_retention_seconds: int = 10


@dataclass(frozen=True, slots=True)
class IdentityConfig:
    """Configuration for identity key storage (ephemeral vs persistent)."""

    is_persistent: bool = False
    storage_path: Optional[str] = None
