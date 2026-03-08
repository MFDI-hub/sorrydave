"""Comprehensive tests for types and exceptions modules."""

import pytest

from sorrydave.exceptions import DaveProtocolError, DecryptionError, InvalidCommitError
from sorrydave.types import (
    DaveConfiguration,
    IdentityConfig,
    ProtocolSupplementalData,
    UnencryptedRange,
)


class TestUnencryptedRange:
    def test_creation(self):
        r = UnencryptedRange(offset=0, length=10)
        assert r.offset == 0
        assert r.length == 10

    def test_frozen(self):
        r = UnencryptedRange(offset=0, length=10)
        with pytest.raises(AttributeError):
            r.offset = 5

    def test_equality(self):
        r1 = UnencryptedRange(offset=0, length=10)
        r2 = UnencryptedRange(offset=0, length=10)
        assert r1 == r2

    def test_inequality(self):
        r1 = UnencryptedRange(offset=0, length=10)
        r2 = UnencryptedRange(offset=0, length=11)
        assert r1 != r2

    def test_hashable(self):
        r = UnencryptedRange(offset=0, length=10)
        {r}  # should not raise


class TestProtocolSupplementalData:
    def test_creation(self):
        data = ProtocolSupplementalData(
            tag_8=b"\x00" * 8,
            nonce_32=42,
            unencrypted_ranges=[],
            supplemental_size=11,
        )
        assert data.tag_8 == b"\x00" * 8
        assert data.nonce_32 == 42
        assert data.unencrypted_ranges == []
        assert data.supplemental_size == 11

    def test_mutable(self):
        data = ProtocolSupplementalData(
            tag_8=b"\x00" * 8, nonce_32=0, unencrypted_ranges=[], supplemental_size=11
        )
        data.nonce_32 = 100
        assert data.nonce_32 == 100


class TestDaveConfiguration:
    def test_defaults(self):
        cfg = DaveConfiguration()
        assert cfg.protocol_version == 1
        assert cfg.mls_ciphersuite == 2
        assert cfg.media_ciphersuite == "AES128-GCM"
        assert cfg.ratchet_retention_seconds == 10

    def test_custom(self):
        cfg = DaveConfiguration(protocol_version=2, mls_ciphersuite=3, ratchet_retention_seconds=60)
        assert cfg.protocol_version == 2
        assert cfg.mls_ciphersuite == 3
        assert cfg.ratchet_retention_seconds == 60

    def test_frozen(self):
        cfg = DaveConfiguration()
        with pytest.raises(AttributeError):
            cfg.protocol_version = 2


class TestIdentityConfig:
    def test_defaults(self):
        cfg = IdentityConfig()
        assert cfg.is_persistent is False
        assert cfg.storage_path is None

    def test_custom(self):
        cfg = IdentityConfig(is_persistent=True, storage_path="/tmp/keys")
        assert cfg.is_persistent is True
        assert cfg.storage_path == "/tmp/keys"

    def test_frozen(self):
        cfg = IdentityConfig()
        with pytest.raises(AttributeError):
            cfg.is_persistent = True


class TestExceptionHierarchy:
    def test_base_exception(self):
        assert issubclass(DaveProtocolError, Exception)

    def test_decryption_is_protocol(self):
        assert issubclass(DecryptionError, DaveProtocolError)

    def test_invalid_commit_is_protocol(self):
        assert issubclass(InvalidCommitError, DaveProtocolError)

    def test_catch_base_catches_decryption(self):
        with pytest.raises(DaveProtocolError):
            raise DecryptionError("test")

    def test_catch_base_catches_invalid_commit(self):
        with pytest.raises(DaveProtocolError):
            raise InvalidCommitError("test")

    def test_message_preserved(self):
        try:
            raise DecryptionError("custom message")
        except DecryptionError as e:
            assert str(e) == "custom message"

    def test_invalid_commit_message(self):
        try:
            raise InvalidCommitError("bad commit")
        except InvalidCommitError as e:
            assert str(e) == "bad commit"

    def test_all_instantiable(self):
        DaveProtocolError("base")
        DecryptionError("decrypt")
        InvalidCommitError("commit")
