"""Tests for per-sender key ratchet (KeyRatchet)."""

import time

import pytest
from sorrydave.crypto.ratchet import KeyRatchet

KEY_16 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"


def test_ratchet_requires_16_byte_base_secret():
    """KeyRatchet rejects base_secret that is not 16 bytes."""
    with pytest.raises(ValueError, match="16 bytes"):
        KeyRatchet(b"short", retention_seconds=1.0)
    with pytest.raises(ValueError, match="16 bytes"):
        KeyRatchet(b"x" * 20, retention_seconds=1.0)


def test_ratchet_get_key_for_generation_deterministic():
    r = KeyRatchet(KEY_16, retention_seconds=10.0)
    k0 = r.get_key_for_generation(0)
    k1 = r.get_key_for_generation(1)
    assert len(k0) == 16
    assert len(k1) == 16
    assert k0 != k1
    # Same generation returns same key (from cache)
    assert r.get_key_for_generation(0) == k0


def test_ratchet_get_key_for_generation_out_of_order():
    """Keys can be requested out of order (e.g. 2, 0, 1) and are consistent."""
    r = KeyRatchet(KEY_16, retention_seconds=10.0)
    r.get_key_for_generation(2)
    k0 = r.get_key_for_generation(0)
    k1 = r.get_key_for_generation(1)
    assert k0 != k1
    assert r.get_key_for_generation(2) == r.get_key_for_generation(2)


def test_ratchet_advance_epoch_clears_cache():
    r = KeyRatchet(KEY_16, retention_seconds=10.0)
    r.get_key_for_generation(0)
    r.get_key_for_generation(1)
    other_secret = bytes([0x10] * 16)  # different from KEY_16
    r.advance_epoch(other_secret)
    # Keys for same generation index should differ after epoch advance (new base secret)
    k_after = r.get_key_for_generation(0)
    r2 = KeyRatchet(KEY_16, retention_seconds=10.0)
    k_original = r2.get_key_for_generation(0)
    assert k_after != k_original


def test_ratchet_max_forward_gap_rejects_large_generation():
    """Generation exceeding max_forward_gap above highest seen raises ValueError."""
    r = KeyRatchet(KEY_16, retention_seconds=10.0, max_forward_gap=64)
    r.get_key_for_generation(0)
    # generation 65 exceeds 0 + 64
    with pytest.raises(ValueError, match="exceeds max forward gap"):
        r.get_key_for_generation(65)


def test_ratchet_max_forward_gap_allows_within_gap():
    r = KeyRatchet(KEY_16, retention_seconds=10.0, max_forward_gap=64)
    r.get_key_for_generation(0)
    k64 = r.get_key_for_generation(64)
    assert len(k64) == 16


def test_ratchet_max_forward_gap_after_advancing_max_seen():
    """Cap is highest_seen + max_forward_gap; 229 fails when highest is 100 and gap 128."""
    r = KeyRatchet(KEY_16, retention_seconds=10.0, max_forward_gap=128)
    r.get_key_for_generation(100)  # cap becomes 100 + 128 = 228
    # 229 should fail
    with pytest.raises(ValueError, match="exceeds max forward gap"):
        r.get_key_for_generation(229)
    r.get_key_for_generation(228)
    assert len(r.get_key_for_generation(228)) == 16


def test_ratchet_max_forward_gap_default():
    """Default max_forward_gap (250, davey MAX_GENERATION_GAP): gen 251 after 0 fails."""
    r = KeyRatchet(KEY_16)
    r.get_key_for_generation(0)
    with pytest.raises(ValueError, match="max forward gap"):
        r.get_key_for_generation(251)


def test_davey_hash_ratchet_generation_0_vector():
    """Lock davey HashRatchet gen-0 key (RFC 9420 §9.1 ExpandWithLabel)."""
    base = bytes.fromhex("cedd61b1b8a1ca69046554282cf70b7b")
    r = KeyRatchet(base)
    assert r.get_key_for_generation(0) == bytes.fromhex("7530f9a9945e2d2e06d0651f7b2a864b")


def test_ratchet_max_forward_gap_must_be_positive():
    """max_forward_gap 0 or negative raises ValueError."""
    with pytest.raises(ValueError, match="at least 1"):
        KeyRatchet(KEY_16, max_forward_gap=0)
    with pytest.raises(ValueError, match="at least 1"):
        KeyRatchet(KEY_16, max_forward_gap=-1)


def test_ratchet_eviction():
    """Only old generations expire; retention starts when a newer key is used."""
    r = KeyRatchet(KEY_16, retention_seconds=0.1)
    key0 = r.get_key_for_generation(0)
    time.sleep(0.15)
    assert r.get_key_for_generation(0) == key0

    r.get_key_for_generation(1)
    assert r.get_key_for_generation(0) == key0
    time.sleep(0.15)
    r.get_key_for_generation(1)
    with pytest.raises(ValueError, match="erased"):
        r.get_key_for_generation(0)
