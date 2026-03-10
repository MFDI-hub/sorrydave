"""Tests for sorrydave.verification: VerificationStore and VerifiedIdentity."""

from __future__ import annotations

import orjson
import os
import tempfile

import pytest

from sorrydave.verification import VerificationStore, VerifiedIdentity


class TestVerifiedIdentity:
    def test_create_with_all_fields(self):
        vi = VerifiedIdentity(user_id=12345, public_key=b"\x04" + b"\xaa" * 64, key_version=1)
        assert vi.user_id == 12345
        assert vi.public_key == b"\x04" + b"\xaa" * 64
        assert vi.key_version == 1

    def test_create_ephemeral_no_key_version(self):
        vi = VerifiedIdentity(user_id=99, public_key=b"\x04" + b"\xbb" * 64)
        assert vi.key_version is None

    def test_equality(self):
        a = VerifiedIdentity(user_id=1, public_key=b"pk1", key_version=1)
        b = VerifiedIdentity(user_id=1, public_key=b"pk1", key_version=1)
        assert a == b

    def test_inequality_different_key(self):
        a = VerifiedIdentity(user_id=1, public_key=b"pk1", key_version=1)
        b = VerifiedIdentity(user_id=1, public_key=b"pk2", key_version=1)
        assert a != b


class TestVerificationStoreBasic:
    def test_empty_store(self):
        store = VerificationStore()
        assert store.get_verified(12345) is None

    def test_add_and_get(self):
        store = VerificationStore()
        store.add_verified(100, b"key100", key_version=1)
        vi = store.get_verified(100)
        assert vi is not None
        assert vi.user_id == 100
        assert vi.public_key == b"key100"
        assert vi.key_version == 1

    def test_add_ephemeral(self):
        store = VerificationStore()
        store.add_verified(200, b"key200")
        vi = store.get_verified(200)
        assert vi is not None
        assert vi.key_version is None

    def test_overwrite(self):
        store = VerificationStore()
        store.add_verified(100, b"old_key", key_version=1)
        store.add_verified(100, b"new_key", key_version=2)
        vi = store.get_verified(100)
        assert vi is not None
        assert vi.public_key == b"new_key"
        assert vi.key_version == 2

    def test_multiple_users(self):
        store = VerificationStore()
        store.add_verified(1, b"key1")
        store.add_verified(2, b"key2")
        store.add_verified(3, b"key3")
        assert store.get_verified(1).public_key == b"key1"
        assert store.get_verified(2).public_key == b"key2"
        assert store.get_verified(3).public_key == b"key3"

    def test_remove(self):
        store = VerificationStore()
        store.add_verified(100, b"key")
        store.remove_verified(100)
        assert store.get_verified(100) is None

    def test_remove_nonexistent(self):
        store = VerificationStore()
        store.remove_verified(9999)


class TestVerificationStoreCheckMatch:
    def test_match_returns_true(self):
        store = VerificationStore()
        store.add_verified(1, b"correct_key")
        assert store.check_match(1, b"correct_key") is True

    def test_mismatch_returns_false(self):
        store = VerificationStore()
        store.add_verified(1, b"correct_key")
        assert store.check_match(1, b"wrong_key") is False

    def test_no_stored_returns_true(self):
        store = VerificationStore()
        assert store.check_match(999, b"any_key") is True

    def test_after_remove_returns_true(self):
        store = VerificationStore()
        store.add_verified(1, b"key")
        store.remove_verified(1)
        assert store.check_match(1, b"different_key") is True

    def test_overwrite_then_check(self):
        store = VerificationStore()
        store.add_verified(1, b"old")
        store.add_verified(1, b"new")
        assert store.check_match(1, b"old") is False
        assert store.check_match(1, b"new") is True


class TestVerificationStorePersistence:
    def test_save_and_load_roundtrip(self):
        store = VerificationStore()
        store.add_verified(111, b"\x04" + b"\xaa" * 32, key_version=1)
        store.add_verified(222, b"\x04" + b"\xbb" * 32, key_version=None)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            store.save_to_path(path)

            with open(path, encoding="utf-8") as f:
                data = orjson.loads(f)
            assert "entries" in data
            assert len(data["entries"]) == 2

            store2 = VerificationStore()
            store2.load_from_path(path)
            vi1 = store2.get_verified(111)
            assert vi1 is not None
            assert vi1.public_key == b"\x04" + b"\xaa" * 32
            assert vi1.key_version == 1

            vi2 = store2.get_verified(222)
            assert vi2 is not None
            assert vi2.public_key == b"\x04" + b"\xbb" * 32
            assert vi2.key_version is None
        finally:
            os.unlink(path)

    def test_load_nonexistent_file_does_nothing(self):
        store = VerificationStore()
        store.load_from_path("/nonexistent/path/to/file.json")
        assert store.get_verified(1) is None

    def test_load_merges_with_existing(self):
        store = VerificationStore()
        store.add_verified(1, b"existing_key")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
            orjson.dumps(
                {
                    "entries": [
                        {
                            "user_id": 2,
                            "public_key": "AAAA",
                            "key_version": 1,
                        }
                    ]
                },
                f,
            )
        try:
            store.load_from_path(path)
            assert store.get_verified(1).public_key == b"existing_key"
            assert store.get_verified(2) is not None
        finally:
            os.unlink(path)

    def test_load_overwrites_same_user(self):
        store = VerificationStore()
        store.add_verified(1, b"old_key", key_version=1)

        import base64

        new_key = b"\x04" + b"\xff" * 32
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
            orjson.dumps(
                {
                    "entries": [
                        {
                            "user_id": 1,
                            "public_key": base64.b64encode(new_key).decode(),
                            "key_version": 2,
                        }
                    ]
                },
                f,
            )
        try:
            store.load_from_path(path)
            vi = store.get_verified(1)
            assert vi.public_key == new_key
            assert vi.key_version == 2
        finally:
            os.unlink(path)

    def test_save_empty_store(self):
        store = VerificationStore()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            store.save_to_path(path)
            with open(path, encoding="utf-8") as f:
                data = orjson.loads(f)
            assert data == {"entries": []}
        finally:
            os.unlink(path)
