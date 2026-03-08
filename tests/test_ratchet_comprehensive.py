"""Comprehensive key ratchet tests: derivation, caching, eviction, epoch advance, edge cases."""

import time

import pytest

from sorrydave.crypto.ratchet import KEY_LENGTH, RATCHET_LABEL, KeyRatchet, sender_base_secret_from_exporter


class TestKeyRatchetInit:
    def test_valid_init(self):
        r = KeyRatchet(b"\x00" * 16)
        assert r._max_generation_seen is None

    def test_wrong_secret_length_raises(self):
        with pytest.raises(ValueError, match="16 bytes"):
            KeyRatchet(b"\x00" * 15)
        with pytest.raises(ValueError, match="16 bytes"):
            KeyRatchet(b"\x00" * 17)
        with pytest.raises(ValueError, match="16 bytes"):
            KeyRatchet(b"")

    def test_max_forward_gap_zero_raises(self):
        with pytest.raises(ValueError, match="at least 1"):
            KeyRatchet(b"\x00" * 16, max_forward_gap=0)

    def test_max_forward_gap_negative_raises(self):
        with pytest.raises(ValueError, match="at least 1"):
            KeyRatchet(b"\x00" * 16, max_forward_gap=-1)

    def test_custom_retention(self):
        r = KeyRatchet(b"\x00" * 16, retention_seconds=30.0)
        assert r._retention_seconds == 30.0


class TestKeyRatchetDerivation:
    def test_key_length(self):
        r = KeyRatchet(b"\x01" * 16)
        key = r.get_key_for_generation(0)
        assert len(key) == KEY_LENGTH

    def test_deterministic(self):
        secret = b"\xAB" * 16
        r1 = KeyRatchet(secret)
        r2 = KeyRatchet(secret)
        assert r1.get_key_for_generation(0) == r2.get_key_for_generation(0)
        assert r1.get_key_for_generation(5) == r2.get_key_for_generation(5)

    def test_different_generations_different_keys(self):
        r = KeyRatchet(b"\x01" * 16, max_forward_gap=300)
        k0 = r.get_key_for_generation(0)
        k1 = r.get_key_for_generation(1)
        k255 = r.get_key_for_generation(255)
        assert k0 != k1
        assert k0 != k255
        assert k1 != k255

    def test_different_secrets_different_keys(self):
        r1 = KeyRatchet(b"\x01" * 16)
        r2 = KeyRatchet(b"\x02" * 16)
        assert r1.get_key_for_generation(0) != r2.get_key_for_generation(0)

    def test_out_of_order_access(self):
        r = KeyRatchet(b"\x01" * 16)
        k5 = r.get_key_for_generation(5)
        k0 = r.get_key_for_generation(0)
        k3 = r.get_key_for_generation(3)
        r2 = KeyRatchet(b"\x01" * 16)
        assert k5 == r2.get_key_for_generation(5)
        assert k0 == r2.get_key_for_generation(0)
        assert k3 == r2.get_key_for_generation(3)

    def test_generation_past_255(self):
        r = KeyRatchet(b"\x01" * 16, max_forward_gap=500)
        k256 = r.get_key_for_generation(256)
        k300 = r.get_key_for_generation(300)
        assert len(k256) == 16
        assert len(k300) == 16
        assert k256 != k300


class TestKeyRatchetCache:
    def test_cache_hit(self):
        r = KeyRatchet(b"\x01" * 16)
        k1 = r.get_key_for_generation(0)
        k2 = r.get_key_for_generation(0)
        assert k1 is k2

    def test_max_generation_tracking(self):
        r = KeyRatchet(b"\x01" * 16)
        r.get_key_for_generation(10)
        assert r._max_generation_seen == 10
        r.get_key_for_generation(5)
        assert r._max_generation_seen == 10
        r.get_key_for_generation(20)
        assert r._max_generation_seen == 20


class TestKeyRatchetForwardGap:
    def test_exceeds_gap_raises(self):
        r = KeyRatchet(b"\x01" * 16, max_forward_gap=10)
        with pytest.raises(ValueError, match="forward gap"):
            r.get_key_for_generation(11)

    def test_within_gap_ok(self):
        r = KeyRatchet(b"\x01" * 16, max_forward_gap=10)
        r.get_key_for_generation(10)

    def test_gap_moves_with_max_seen(self):
        r = KeyRatchet(b"\x01" * 16, max_forward_gap=10)
        r.get_key_for_generation(5)
        r.get_key_for_generation(15)
        with pytest.raises(ValueError):
            r.get_key_for_generation(26)

    def test_gap_from_zero_when_nothing_seen(self):
        r = KeyRatchet(b"\x01" * 16, max_forward_gap=64)
        r.get_key_for_generation(64)
        with pytest.raises(ValueError):
            r.get_key_for_generation(65 + 64)


class TestKeyRatchetEviction:
    def test_eviction_after_retention(self):
        r = KeyRatchet(b"\x01" * 16, retention_seconds=0.05, max_forward_gap=1000)
        k0 = r.get_key_for_generation(0)
        time.sleep(0.1)
        k0_after = r.get_key_for_generation(0)
        assert k0 == k0_after

    def test_non_expired_entries_kept(self):
        r = KeyRatchet(b"\x01" * 16, retention_seconds=10.0)
        r.get_key_for_generation(0)
        r.get_key_for_generation(1)
        assert 0 in r._cache
        assert 1 in r._cache


class TestKeyRatchetAdvanceEpoch:
    def test_advance_clears_cache(self):
        r = KeyRatchet(b"\x01" * 16)
        k0_old = r.get_key_for_generation(0)
        r.advance_epoch(b"\x02" * 16)
        k0_new = r.get_key_for_generation(0)
        assert k0_old != k0_new

    def test_advance_resets_max_generation(self):
        r = KeyRatchet(b"\x01" * 16)
        r.get_key_for_generation(50)
        r.advance_epoch(b"\x02" * 16)
        assert r._max_generation_seen is None

    def test_advance_bad_secret_raises(self):
        r = KeyRatchet(b"\x01" * 16)
        with pytest.raises(ValueError, match="16 bytes"):
            r.advance_epoch(b"\x02" * 8)


class TestSenderBaseSecretFromExporter:
    def test_returns_exporter_result(self):
        secret = b"\xCD" * 16
        result = sender_base_secret_from_exporter(lambda: secret)
        assert result == secret
