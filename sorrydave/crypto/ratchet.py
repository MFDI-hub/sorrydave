"""
Per-sender key ratchet derived from MLS-Exporter base secret.
"""

import time
from typing import Callable, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# Label for per-generation key derivation (MLS-style sender ratchet)
RATCHET_LABEL = b"Discord Secure Frames key"
KEY_LENGTH = 16


class KeyRatchet:
    """
    Derives 128-bit AES keys for each generation from a sender base secret.

    Caches recent keys for out-of-order decryption. Enforces a maximum forward
    gap from the highest generation seen (DoS mitigation).
    """

    def __init__(
        self,
        base_secret: bytes,
        retention_seconds: float = 10.0,
        max_forward_gap: int = 64,
    ):
        """
        Initialize the key ratchet.

        Args:
            base_secret (bytes): 16-byte sender base secret (e.g. from MLS exporter).
            retention_seconds (float): How long to cache keys for out-of-order decryption.
            max_forward_gap (int): Max generations ahead of highest seen (DoS limit).

        Raises:
            ValueError: If base_secret is not 16 bytes or max_forward_gap < 1.
        """
        if len(base_secret) != KEY_LENGTH:
            raise ValueError("base_secret must be 16 bytes")
        if max_forward_gap < 1:
            raise ValueError("max_forward_gap must be at least 1")
        self._base_secret = base_secret
        self._retention_seconds = retention_seconds
        self._max_forward_gap = max_forward_gap
        self._cache: dict[int, tuple[bytes, float]] = {}
        self._max_generation_seen: Union[int, None] = None

    def get_key_for_generation(self, generation: int) -> bytes:
        """
        Return the 16-byte key for the given generation.

        Advances cache as needed. Evicts expired entries before lookup.

        Args:
            generation (int): Generation index (e.g. from nonce MSB).

        Returns:
            bytes: 16-byte AES key for that generation.

        Raises:
            ValueError: If generation was evicted (too old) or exceeds
                highest seen + max_forward_gap (DoS protection).
        """
        now = time.monotonic()
        self._evict_expired(now)
        cap = (
            self._max_generation_seen if self._max_generation_seen is not None else 0
        ) + self._max_forward_gap
        if generation > cap:
            raise ValueError(
                f"Generation {generation} exceeds max forward gap (cap {cap}); "
                "rejecting to prevent DoS via excessive HKDF derivations"
            )
        if generation in self._cache:
            return self._cache[generation][0]
        # Derive key for this generation (and optionally cache intermediate for forward progress)
        key = self._derive(generation)
        self._cache[generation] = (key, now)
        if self._max_generation_seen is None or generation > self._max_generation_seen:
            self._max_generation_seen = generation
        return key

    def _derive(self, generation: int) -> bytes:
        """
        Derive 16-byte key for generation via HKDF-expand.

        Args:
            generation (int): Generation index (32-bit little-endian in context).

        Returns:
            bytes: 16-byte key.
        """
        # Generation can exceed 255 after nonce wrap; use 4-byte little-endian
        info = RATCHET_LABEL + (generation & 0xFFFFFFFF).to_bytes(4, "little")
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            info=info,
        )
        return hkdf.derive(self._base_secret)

    def _evict_expired(self, now: float) -> None:
        """
        Remove cache entries older than retention_seconds.

        Args:
            now (float): Current monotonic time (e.g. time.monotonic()).
        """
        expired = [g for g, (_, t) in self._cache.items() if now - t > self._retention_seconds]
        for g in expired:
            del self._cache[g]

    def advance_epoch(self, new_base_secret: bytes) -> None:
        """
        Replace base secret for new MLS epoch and clear cache.

        Args:
            new_base_secret (bytes): New 16-byte sender base secret.

        Raises:
            ValueError: If new_base_secret is not 16 bytes.
        """
        if len(new_base_secret) != KEY_LENGTH:
            raise ValueError("new_base_secret must be 16 bytes")
        self._base_secret = new_base_secret
        self._cache.clear()
        self._max_generation_seen = None


def sender_base_secret_from_exporter(export_fn: Callable[[], bytes]) -> bytes:
    """
    Obtain 16-byte sender base secret by calling the MLS exporter.

    export_fn should invoke MLS-Exporter("Discord Secure Frames v0", context, 16)
    with context = little-endian 64-bit sender user ID.

    Args:
        export_fn (Callable[[], bytes]): Callable that returns the exported secret.

    Returns:
        bytes: 16-byte base secret for KeyRatchet.
    """
    result: bytes = export_fn()
    return result
