"""
DAVE protocol data structures and configuration types.
"""

from dataclasses import dataclass
from typing import Union


@dataclass(frozen=True, slots=True)
class UnencryptedRange:
    """
    Byte range that must remain plaintext for SFU routing (e.g. codec headers).

    Attributes:
        offset (int): Start offset in the frame.
        length (int): Number of bytes in the range.
    """

    offset: int
    length: int


@dataclass(slots=True)
class ProtocolSupplementalData:
    """
    Parsed DAVE protocol footer (supplemental data).

    Layout: 8-byte tag, ULEB128 nonce, ULEB128 offset/length pairs, 1-byte size, 2-byte magic 0xFAFA.

    Attributes:
        tag_8 (bytes): 8-byte GCM authentication tag.
        nonce_32 (int): 32-bit truncated nonce.
        unencrypted_ranges (list[UnencryptedRange]): Ranges left in plaintext.
        supplemental_size (int): Total supplemental block size in bytes.
    """

    tag_8: bytes
    nonce_32: int
    unencrypted_ranges: list[UnencryptedRange]
    supplemental_size: int


@dataclass(frozen=True, slots=True)
class DaveConfiguration:
    """
    Immutable configuration for DAVE protocol version and ciphersuite.

    Attributes:
        protocol_version (int): DAVE protocol version. Defaults to 1.
        mls_ciphersuite (int): MLS ciphersuite ID (e.g. 2 = DHKEMP256_AES128GCM_SHA256_P256).
        media_ciphersuite (str): Media encryption cipher. Defaults to "AES128-GCM".
        ratchet_retention_seconds (int): Key ratchet cache retention in seconds.
    """

    protocol_version: int = 1
    mls_ciphersuite: int = 2  # DHKEMP256_AES128GCM_SHA256_P256
    media_ciphersuite: str = "AES128-GCM"
    ratchet_retention_seconds: int = 10


@dataclass(frozen=True, slots=True)
class IdentityConfig:
    """
    Configuration for identity key storage (ephemeral vs persistent).

    Attributes:
        is_persistent (bool): Whether to persist keys. Defaults to False.
        storage_path (Union[str, None]): Path for persistent storage. None if ephemeral.
    """

    is_persistent: bool = False
    storage_path: Union[str, None] = None
