"""
Per-sender key ratchet derived from MLS-Exporter base secret.

Matches Discord libdave / davey HashRatchet: RFC 9420 §9.1 chained
ExpandWithLabel("key" / "nonce" / "secret") with MLS++ length handling
(16-byte exporter secret, 32-byte subsequent secrets).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Callable, Union

KEY_LENGTH = 16
NONCE_LENGTH = 12
HASH_LENGTH = 32  # SHA-256 Nh
DEFAULT_MAX_FORWARD_GAP = 250  # davey MAX_GENERATION_GAP


def _write_varint(n: int) -> bytes:
    """RFC 9420 §2.1.2 variable-size integer (used as VLBytes length)."""
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x4000).to_bytes(2, "big")
    if n <= 0x3FFFFFFF:
        return (n | 0x80000000).to_bytes(4, "big")
    raise ValueError("integer too large for RFC 9420 varint")


def _write_opaque_varint(data: bytes) -> bytes:
    return _write_varint(len(data)) + data


def _hkdf_expand(prk: bytes, info: bytes, size: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256, matching MLS++ / davey."""
    okm = bytearray()
    i = 0
    ti = b""
    while len(okm) < size:
        i += 1
        block = ti + info + bytes([i])
        ti = hmac.new(prk, block, hashlib.sha256).digest()
        okm.extend(ti)
    return bytes(okm[:size])


def expand_with_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """RFC 9420 ExpandWithLabel; label is prefixed with ``MLS 1.0 ``."""
    mls_label = f"MLS 1.0 {label}".encode("ascii")
    kdf_label = (length).to_bytes(2, "big") + _write_opaque_varint(mls_label) + _write_opaque_varint(
        context
    )
    return _hkdf_expand(secret, kdf_label, length)


def derive_tree_secret(secret: bytes, label: str, generation: int, length: int) -> bytes:
    """RFC 9420 DeriveTreeSecret(secret, label, generation, length)."""
    gen_be = (generation & 0xFFFFFFFF).to_bytes(4, "big")
    return expand_with_label(secret, label, gen_be, length)


class KeyRatchet:
    """
    Derives 128-bit AES keys for each generation from a sender base secret.

    Used by the session for send/receive keys (FrameEncryptor and FrameDecryptor).
    Caches recent keys for out-of-order decryption. Enforces a maximum forward
    gap from the highest generation seen (DoS mitigation).

    Generations are chained: secret_{n+1} = ExpandWithLabel(secret_n, "secret", n, 32).
    The per-generation 12-byte ratchet nonce is derived then unused; DAVE GCM
    uses the truncated sync nonce expanded with leading zeros.
    """

    def __init__(
        self,
        base_secret: bytes,
        retention_seconds: float = 10.0,
        max_forward_gap: int = DEFAULT_MAX_FORWARD_GAP,
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
        self._next_secret = bytes(base_secret)
        self._next_generation = 0
        self._retention_seconds = retention_seconds
        self._max_forward_gap = max_forward_gap
        self._cache: dict[int, tuple[bytes, float]] = {}
        self._max_generation_seen: Union[int, None] = None

    def get_key_for_generation(self, generation: int) -> bytes:
        """
        Return the 16-byte key for the given generation.

        Advances the hash ratchet as needed. Evicts expired entries before lookup.
        Erased generations that have already been ratcheted past cannot be recovered.

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
        if self._next_generation > generation:
            raise ValueError(
                f"Generation {generation} was erased and cannot be re-derived"
            )
        while self._next_generation <= generation:
            self._advance()
        return self._cache[generation][0]

    def _advance(self) -> None:
        """Ratchet forward one generation (RFC 9420 §9.1 HashRatchet.Next)."""
        generation = self._next_generation
        key = derive_tree_secret(self._next_secret, "key", generation, KEY_LENGTH)
        derive_tree_secret(self._next_secret, "nonce", generation, NONCE_LENGTH)
        self._next_secret = derive_tree_secret(
            self._next_secret, "secret", generation, HASH_LENGTH
        )
        self._next_generation = (self._next_generation + 1) & 0xFFFFFFFF
        now = time.monotonic()
        if (
            self._max_generation_seen is not None
            and generation > self._max_generation_seen
            and self._max_generation_seen in self._cache
        ):
            previous_key, _ = self._cache[self._max_generation_seen]
            # Retention starts when a generation becomes old, not when its key
            # was first derived. The active generation must remain usable for
            # an arbitrarily long epoch.
            self._cache[self._max_generation_seen] = (previous_key, now)
        self._cache[generation] = (key, now)
        if self._max_generation_seen is None or generation > self._max_generation_seen:
            self._max_generation_seen = generation

    def _evict_expired(self, now: float) -> None:
        """
        Remove cache entries older than retention_seconds.

        Args:
            now (float): Current monotonic time (e.g. time.monotonic()).
        """
        expired = [
            generation
            for generation, (_, retained_at) in self._cache.items()
            if generation != self._max_generation_seen
            and now - retained_at > self._retention_seconds
        ]
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
        self._next_secret = bytes(new_base_secret)
        self._next_generation = 0
        self._cache.clear()
        self._max_generation_seen = None


def sender_base_secret_from_exporter(export_fn: Callable[[], bytes]) -> bytes:
    """
    Obtain 16-byte sender base secret by calling the MLS exporter.

    Used when building KeyRatchet for a sender (session refresh after commit/welcome/
    execute transition). export_fn should invoke MLS-Exporter("Discord Secure Frames v0",
    context, 16) with context = little-endian 64-bit sender user ID.

    Args:
        export_fn (Callable[[], bytes]): Callable that returns the exported secret.

    Returns:
        bytes: 16-byte base secret for KeyRatchet.
    """
    result: bytes = export_fn()
    return result
