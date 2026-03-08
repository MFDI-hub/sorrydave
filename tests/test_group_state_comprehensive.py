"""Comprehensive group_state tests: key packages, group creation, exports, extensions, validation."""

import pytest

from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.group_state import (
    DAVE_MLS_CIPHERSUITE_ID,
    EXPORTER_LABEL,
    EXPORTER_LENGTH,
    EXTENSION_TYPE_EXTERNAL_SENDERS,
    _check_no_duplicate_credentials,
    _read_opaque_varint,
    _read_varint,
    _write_opaque_varint,
    _write_varint,
    apply_commit,
    create_commit_and_welcome,
    create_group,
    create_key_package,
    create_remove_proposal_for_self,
    create_update_proposal,
    export_sender_base_secret,
    get_dave_crypto_provider,
    get_external_senders_from_group,
    join_from_welcome,
    serialize_external_senders_extension,
    validate_group_external_sender,
)


@pytest.fixture
def crypto():
    return get_dave_crypto_provider()


@pytest.fixture
def key_package_tuple(crypto):
    return create_key_package(123456789, crypto)


@pytest.fixture
def group_with_ext(crypto, key_package_tuple):
    kp_bytes, _, _ = key_package_tuple
    return create_group(
        b"test-group",
        kp_bytes,
        crypto,
        external_sender_signature_key=b"\xAA" * 65,
        external_sender_credential_type=1,
        external_sender_identity=b"\x00" * 8,
    )


class TestGetDaveCryptoProvider:
    def test_returns_provider(self, crypto):
        assert crypto is not None
        assert hasattr(crypto, "generate_key_pair")

    def test_idempotent(self):
        c1 = get_dave_crypto_provider()
        c2 = get_dave_crypto_provider()
        assert type(c1) == type(c2)


class TestCreateKeyPackage:
    def test_returns_tuple_of_three(self, crypto):
        kp_bytes, hpke_private, signing_der = create_key_package(1, crypto)
        assert isinstance(kp_bytes, bytes)
        assert isinstance(hpke_private, bytes)
        assert isinstance(signing_der, bytes)
        assert len(kp_bytes) > 0
        assert len(hpke_private) > 0
        assert len(signing_der) > 0

    def test_different_users_different_kps(self, crypto):
        kp1, _, _ = create_key_package(1, crypto)
        kp2, _, _ = create_key_package(2, crypto)
        assert kp1 != kp2

    def test_default_crypto(self):
        kp, hpke, sig = create_key_package(42)
        assert len(kp) > 0

    def test_large_user_id(self, crypto):
        kp, _, _ = create_key_package((1 << 63) - 1, crypto)
        assert len(kp) > 0


class TestCreateGroup:
    def test_single_member(self, crypto, key_package_tuple):
        kp_bytes, _, _ = key_package_tuple
        group = create_group(b"test-group", kp_bytes, crypto)
        assert group is not None
        assert group._inner.get_member_count() == 1

    def test_with_external_sender(self, group_with_ext):
        assert group_with_ext is not None
        assert group_with_ext._inner.get_member_count() == 1

    def test_default_crypto(self, key_package_tuple):
        kp_bytes, _, _ = key_package_tuple
        group = create_group(b"default-crypto-group", kp_bytes)
        assert group is not None


class TestExportSenderBaseSecret:
    def test_returns_16_bytes(self, crypto, key_package_tuple):
        kp_bytes, _, _ = key_package_tuple
        group = create_group(b"test-export", kp_bytes, crypto)
        secret = export_sender_base_secret(group, 123456789)
        assert len(secret) == EXPORTER_LENGTH

    def test_different_user_ids_different_secrets(self, crypto, key_package_tuple):
        kp_bytes, _, _ = key_package_tuple
        group = create_group(b"test-export-2", kp_bytes, crypto)
        s1 = export_sender_base_secret(group, 1)
        s2 = export_sender_base_secret(group, 2)
        assert s1 != s2

    def test_deterministic(self, crypto, key_package_tuple):
        kp_bytes, _, _ = key_package_tuple
        group = create_group(b"test-det", kp_bytes, crypto)
        s1 = export_sender_base_secret(group, 42)
        s2 = export_sender_base_secret(group, 42)
        assert s1 == s2


class TestApplyCommit:
    def test_invalid_commit_raises(self, crypto, key_package_tuple):
        kp_bytes, _, _ = key_package_tuple
        group = create_group(b"test-apply", kp_bytes, crypto)
        with pytest.raises(InvalidCommitError):
            apply_commit(group, b"\x00\x01\x02", 0)


class TestJoinFromWelcome:
    def test_invalid_welcome_raises(self, crypto):
        with pytest.raises(Exception):
            join_from_welcome(b"\x00\x01\x02", b"\x00" * 32, crypto)


class TestWriteVarint:
    def test_small_value(self):
        result = _write_varint(5)
        assert result == bytes([5])

    def test_two_byte(self):
        result = _write_varint(0x100)
        assert len(result) == 2

    def test_four_byte(self):
        result = _write_varint(0x10000)
        assert len(result) == 4

    def test_too_large_raises(self):
        with pytest.raises(ValueError, match="too large"):
            _write_varint(0x40000000)

    @pytest.mark.parametrize("value", [0, 1, 0x3F, 0x40, 0x3FFF, 0x4000, 0x3FFFFFFF])
    def test_roundtrip(self, value):
        encoded = _write_varint(value)
        decoded, off = _read_varint(encoded, 0)
        assert decoded == value
        assert off == len(encoded)


class TestOpaqueVarintGroupState:
    def test_roundtrip(self):
        payload = b"test payload"
        encoded = _write_opaque_varint(payload)
        decoded, off = _read_opaque_varint(encoded, 0)
        assert decoded == payload
        assert off == len(encoded)


class TestSerializeExternalSendersExtension:
    def test_basic(self):
        result = serialize_external_senders_extension(
            signature_key=b"\xAA" * 32,
            credential_type=1,
            identity=b"\x00" * 8,
        )
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_contains_extension_type(self):
        result = serialize_external_senders_extension(
            signature_key=b"\xBB" * 32,
            credential_type=1,
            identity=b"\x01" * 8,
        )
        import struct
        ext_type = struct.unpack("!H", result[:2])[0]
        assert ext_type == EXTENSION_TYPE_EXTERNAL_SENDERS


class TestCheckNoDuplicateCredentials:
    def test_single_member_no_error(self, group_with_ext):
        _check_no_duplicate_credentials(group_with_ext)


class TestCreateCommitAndWelcome:
    def test_basic_commit_after_update(self, crypto):
        """Create a commit after an update proposal (avoids cross-user kp signature issues)."""
        kp_bytes, _, signing_der = create_key_package(1, crypto)
        group = create_group(b"commit-group", kp_bytes, crypto)
        update_bytes = create_update_proposal(group, signing_der, 1, crypto)
        commit_bytes, welcomes = create_commit_and_welcome(group, signing_der)
        assert isinstance(commit_bytes, bytes)
        assert len(commit_bytes) > 0
        assert isinstance(welcomes, list)


class TestCreateRemoveProposalForSelf:
    def test_returns_bytes(self, crypto):
        kp_bytes, _, signing_der = create_key_package(1, crypto)
        group = create_group(b"remove-group", kp_bytes, crypto)
        result = create_remove_proposal_for_self(group, signing_der)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestCreateUpdateProposal:
    def test_returns_bytes(self, crypto):
        kp_bytes, _, signing_der = create_key_package(1, crypto)
        group = create_group(b"update-group", kp_bytes, crypto)
        result = create_update_proposal(group, signing_der, 1, crypto)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestProtocolConstants:
    def test_ciphersuite(self):
        assert DAVE_MLS_CIPHERSUITE_ID == 2

    def test_exporter_label(self):
        assert EXPORTER_LABEL == b"Discord Secure Frames v0"

    def test_exporter_length(self):
        assert EXPORTER_LENGTH == 16

    def test_extension_type(self):
        assert EXTENSION_TYPE_EXTERNAL_SENDERS == 0x0002
