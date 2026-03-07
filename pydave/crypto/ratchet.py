"""
Per-sender key ratchet derived from MLS-Exporter base secret.
"""

import time
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# Label for per-generation key derivation (MLS-style sender ratchet)
RATCHET_LABEL = b"Discord Secure Frames key"
KEY_LENGTH = 16


class KeyRatchet:
    """
    Derives 128-bit AES keys for each generation from a sender base secret.
    Caches recent keys for out-of-order decryption (e.g. up to 10 seconds).
    """

    def __init__(self, base_secret: bytes, retention_seconds: float = 10.0):
        if len(base_secret) != KEY_LENGTH:
            raise ValueError("base_secret must be 16 bytes")
        self._base_secret = base_secret
        self._retention_seconds = retention_seconds
        self._cache: dict[int, tuple[bytes, float]] = {}
        self._max_generation_seen: Optional[int] = None

    def get_key_for_generation(self, generation: int) -> bytes:
        """
        Return the 16-byte key for the given generation. Advances cache as needed.
        Raises ValueError if generation was evicted (too old).
        """
        now = time.monotonic()
        self._evict_expired(now)
        if generation in self._cache:
            return self._cache[generation][0]
        # Derive key for this generation (and optionally cache intermediate for forward progress)
        key = self._derive(generation)
        self._cache[generation] = (key, now)
        if self._max_generation_seen is None or generation > self._max_generation_seen:
            self._max_generation_seen = generation
        return key

    def _derive(self, generation: int) -> bytes:
        """HKDF-expand from base_secret with context = generation (32-bit little-endian)."""
        info = RATCHET_LABEL + generation.to_bytes(4, "little")
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            info=info,
        )
        return hkdf.derive(self._base_secret)

    def _evict_expired(self, now: float) -> None:
        """Remove cache entries older than retention_seconds."""
        expired = [g for g, (_, t) in self._cache.items() if now - t > self._retention_seconds]
        for g in expired:
            del self._cache[g]

    def advance_epoch(self, new_base_secret: bytes) -> None:
        """Replace base secret for new MLS epoch; clear cache."""
        if len(new_base_secret) != KEY_LENGTH:
            raise ValueError("new_base_secret must be 16 bytes")
        self._base_secret = new_base_secret
        self._cache.clear()
        self._max_generation_seen = None


def sender_base_secret_from_exporter(export_fn: Callable[[], bytes]) -> bytes:
    """
    Call export_fn() which should invoke MLS-Exporter("Discord Secure Frames v0", context, 16).
    context = little-endian 64-bit sender user ID.
    Returns 16-byte base secret for KeyRatchet.
    """
    result: bytes = export_fn()
    return result
