"""
Verification state storage: persistent and ephemeral verified identity keys.

Stores verified public keys per user for identity verification (protocol.md
§Performing Verification). Supports mismatch detection when a user's key
differs from the previously verified key.
"""

import orjson
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class VerifiedIdentity:
    """
    Stored verified identity for one user.

    Attributes:
        user_id (int): Discord user ID (snowflake).
        public_key (bytes): Verified P256 public key (X9.62).
        key_version (Optional[int]): Key version if persistent; None for ephemeral.
    """

    user_id: int
    public_key: bytes
    key_version: Optional[int] = None


class VerificationStore:
    """
    In-memory store of verified user identities (ephemeral and persistent).

    Use add_verified() after out-of-band verification. Use check_match() in a
    call to see if the key presented by a user matches the previously verified key.
    Mismatch detection: check_match() returns False when a different key is
    presented than the one stored.
    """

    def __init__(self) -> None:
        self._store: dict[int, VerifiedIdentity] = {}

    def add_verified(
        self,
        user_id: int,
        public_key: bytes,
        key_version: Optional[int] = None,
    ) -> None:
        """
        Store a verified identity for a user.

        Call after completing out-of-band verification (manual compare or deeplink).

        Args:
            user_id (int): Verified user's Discord ID.
            public_key (bytes): Their P256 public key (X9.62).
            key_version (Optional[int]): Key version for persistent keys; omit for ephemeral.
        """
        self._store[user_id] = VerifiedIdentity(
            user_id=user_id,
            public_key=public_key,
            key_version=key_version,
        )

    def get_verified(self, user_id: int) -> Optional[VerifiedIdentity]:
        """
        Return the stored verified identity for a user, if any.

        Args:
            user_id (int): Discord user ID.

        Returns:
            Optional[VerifiedIdentity]: Stored entry or None.
        """
        return self._store.get(user_id)

    def check_match(self, user_id: int, public_key: bytes) -> bool:
        """
        Check if the given public key matches the previously verified key for this user.

        Returns True if there is no stored verification (no mismatch) or if the
        key matches. Returns False when we have a stored key and it differs
        (mismatch: different device, key replacement, or impersonation).

        Args:
            user_id (int): User ID whose key is being checked.
            public_key (bytes): Key presented in the current call.

        Returns:
            bool: True if match or no stored verification; False if mismatch.
        """
        entry = self._store.get(user_id)
        if entry is None:
            return True
        return entry.public_key == public_key

    def remove_verified(self, user_id: int) -> None:
        """Remove stored verification for a user."""
        self._store.pop(user_id, None)

    def save_to_path(self, path: str) -> None:
        """
        Persist the store to a JSON file (public_key and signature as base64).

        Only entries with key_version set are typically stored for persistent
        verification; ephemeral entries can be included but are lost on app restart
        unless saved here.

        Args:
            path (str): File path to write.
        """
        import base64

        data: dict[str, Any] = {
            "entries": [
                {
                    "user_id": e.user_id,
                    "public_key": base64.b64encode(e.public_key).decode("ascii"),
                    "key_version": e.key_version,
                }
                for e in self._store.values()
            ]
        }
        with open(path, "w", encoding="utf-8") as f:
            orjson.dumps(data, f, indent=2)

    def load_from_path(self, path: str) -> None:
        """
        Load verified identities from a JSON file.

        Merges with existing in-memory store (overwrites same user_id). Does
        nothing if the file does not exist.

        Args:
            path (str): File path to read.
        """
        import base64
        import os

        if not os.path.isfile(path):
            return
        with open(path, encoding="utf-8") as f:
            data = orjson.loads(f)
        for item in data.get("entries", []):
            user_id = int(item["user_id"])
            public_key = base64.b64decode(item["public_key"])
            key_version = item.get("key_version")
            self._store[user_id] = VerifiedIdentity(
                user_id=user_id,
                public_key=public_key,
                key_version=key_version,
            )
