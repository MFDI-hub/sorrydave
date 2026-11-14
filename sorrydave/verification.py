"""
Verification state storage: persistent and ephemeral verified identity keys.

Stores verified public keys per user for identity verification (protocol.md
§Performing Verification). Supports mismatch detection when a user's key
differs from the previously verified key.
"""

from dataclasses import dataclass
from typing import Any, Union

import orjson


@dataclass
class VerifiedIdentity:
    """
    Stored verified identity for one user.

    Attributes:
        user_id (int): Discord user ID (snowflake).
        public_key (bytes): Verified P256 public key (X9.62).
        key_version (Union[int, None]): Key version if persistent; None for ephemeral.
    """

    user_id: int
    public_key: bytes
    key_version: Union[int, None] = None


class VerificationStore:
    """
    In-memory store of verified user identities (ephemeral and persistent).

    Use add_verified() after out-of-band verification. check_match() returns
    True on a match, False when a different key is stored, and None when the
    user has never been verified.
    """

    def __init__(self) -> None:
        self._store: dict[int, VerifiedIdentity] = {}

    def add_verified(
        self,
        user_id: int,
        public_key: bytes,
        key_version: Union[int, None] = None,
    ) -> None:
        """
        Store a verified identity for a user.

        Call after completing out-of-band verification (manual compare or deeplink).

        Args:
            user_id (int): Verified user's Discord ID.
            public_key (bytes): Their P256 public key (X9.62).
            key_version (Union[int, None]): Key version for persistent keys; omit for ephemeral.
        """
        self._store[user_id] = VerifiedIdentity(
            user_id=user_id,
            public_key=public_key,
            key_version=key_version,
        )

    def get_verified(self, user_id: int) -> Union[VerifiedIdentity, None]:
        """
        Return the stored verified identity for a user, if any.

        Args:
            user_id (int): Discord user ID.

        Returns:
            Union[VerifiedIdentity, None]: Stored entry or None.
        """
        return self._store.get(user_id)

    def check_match(self, user_id: int, public_key: bytes) -> Union[bool, None]:
        """
        Compare a presented key with the stored verified key.

        Args:
            user_id (int): User ID whose key is being checked.
            public_key (bytes): Key presented in the current call.

        Returns:
            Union[bool, None]: True if it matches the stored key, False if a
            different key is stored, None if this user has never been verified.
        """
        entry = self._store.get(user_id)
        if entry is None:
            return None
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
        payload = orjson.dumps(data, option=orjson.OPT_INDENT_2)
        with open(path, "wb") as f:
            f.write(payload)

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
        with open(path, "rb") as f:
            data = orjson.loads(f.read())
        for item in data.get("entries", []):
            user_id = int(item["user_id"])
            public_key = base64.b64decode(item["public_key"])
            key_version = item.get("key_version")
            self._store[user_id] = VerifiedIdentity(
                user_id=user_id,
                public_key=public_key,
                key_version=key_version,
            )
