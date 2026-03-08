"""Comprehensive identity tests: displayable_code, fingerprint, epoch authenticator."""

import pytest

from sorrydave.identity import (
    EPOCH_AUTH_DIGITS,
    EPOCH_AUTH_GROUP_SIZE,
    FINGERPRINT_SALT,
    FINGERPRINT_VERSION,
    PAIRWISE_DIGITS,
    PAIRWISE_GROUP_SIZE,
    SCRYPT_DKLEN,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    displayable_code,
    epoch_authenticator_display,
    generate_fingerprint,
)


class TestDisplayableCode:
    def test_basic(self):
        data = bytes(range(45))
        result = displayable_code(data, 45, 5)
        assert len(result) == 45
        assert result.isdigit()

    def test_zero_padded(self):
        data = b"\x00" * 45
        result = displayable_code(data, 45, 5)
        assert result == "0" * 45

    def test_group_size_1(self):
        data = b"\x05\x09"
        result = displayable_code(data, 2, 1)
        assert result == "59"

    def test_modulo_applied(self):
        data = bytes([0xFF]) * 5
        result = displayable_code(data, 5, 5)
        assert len(result) == 5
        expected = int.from_bytes(b"\xFF" * 5, "big") % 100000
        assert result == str(expected).zfill(5)

    def test_total_not_multiple_raises(self):
        with pytest.raises(ValueError, match="multiple"):
            displayable_code(b"\x00" * 10, 7, 5)

    def test_group_size_too_large_raises(self):
        with pytest.raises(ValueError, match="smaller than 8"):
            displayable_code(b"\x00" * 40, 8, 8)

    def test_data_too_short_raises(self):
        with pytest.raises(ValueError, match="Need at least"):
            displayable_code(b"\x00" * 4, 5, 5)

    def test_deterministic(self):
        data = bytes(range(45))
        r1 = displayable_code(data, 45, 5)
        r2 = displayable_code(data, 45, 5)
        assert r1 == r2

    def test_different_data_different_codes(self):
        d1 = bytes([0x01]) * 45
        d2 = bytes([0x02]) * 45
        assert displayable_code(d1, 45, 5) != displayable_code(d2, 45, 5)


class TestGenerateFingerprint:
    def test_returns_45_digits(self):
        result = generate_fingerprint(1, b"\x01" * 32, 2, b"\x02" * 32)
        assert len(result) == PAIRWISE_DIGITS
        assert result.isdigit()

    def test_symmetric(self):
        fp1 = generate_fingerprint(1, b"\x01" * 32, 2, b"\x02" * 32)
        fp2 = generate_fingerprint(2, b"\x02" * 32, 1, b"\x01" * 32)
        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self):
        fp1 = generate_fingerprint(1, b"\x01" * 32, 2, b"\x02" * 32)
        fp2 = generate_fingerprint(1, b"\x01" * 32, 2, b"\x03" * 32)
        assert fp1 != fp2

    def test_different_ids_different_fingerprints(self):
        fp1 = generate_fingerprint(1, b"\x01" * 32, 2, b"\x02" * 32)
        fp2 = generate_fingerprint(1, b"\x01" * 32, 3, b"\x02" * 32)
        assert fp1 != fp2

    def test_deterministic(self):
        fp1 = generate_fingerprint(42, b"\xAA" * 32, 99, b"\xBB" * 32)
        fp2 = generate_fingerprint(42, b"\xAA" * 32, 99, b"\xBB" * 32)
        assert fp1 == fp2

    def test_same_user_same_key(self):
        result = generate_fingerprint(1, b"\x01" * 32, 1, b"\x01" * 32)
        assert len(result) == 45
        assert result.isdigit()


class TestEpochAuthenticatorDisplay:
    def test_returns_30_digits(self):
        data = bytes(range(32))
        result = epoch_authenticator_display(data)
        assert len(result) == EPOCH_AUTH_DIGITS
        assert result.isdigit()

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="at least 30"):
            epoch_authenticator_display(b"\x00" * 29)

    def test_exactly_30_bytes(self):
        data = bytes(range(30))
        result = epoch_authenticator_display(data)
        assert len(result) == 30

    def test_deterministic(self):
        data = b"\xAB" * 32
        r1 = epoch_authenticator_display(data)
        r2 = epoch_authenticator_display(data)
        assert r1 == r2


class TestProtocolConstants:
    def test_salt_length(self):
        assert len(FINGERPRINT_SALT) == 16

    def test_version(self):
        assert FINGERPRINT_VERSION == bytes((0x00, 0x00))

    def test_scrypt_params(self):
        assert SCRYPT_N == 16384
        assert SCRYPT_R == 8
        assert SCRYPT_P == 2
        assert SCRYPT_DKLEN == 64

    def test_pairwise_digits(self):
        assert PAIRWISE_DIGITS == 45
        assert PAIRWISE_GROUP_SIZE == 5
        assert PAIRWISE_DIGITS % PAIRWISE_GROUP_SIZE == 0

    def test_epoch_auth_digits(self):
        assert EPOCH_AUTH_DIGITS == 30
        assert EPOCH_AUTH_GROUP_SIZE == 5
        assert EPOCH_AUTH_DIGITS % EPOCH_AUTH_GROUP_SIZE == 0
