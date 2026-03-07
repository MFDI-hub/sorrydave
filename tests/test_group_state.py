"""Tests for MLS group state (create_key_package, create_group, commit, export, etc.)."""

import pytest
from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.group_state import (
    apply_commit,
    create_commit_and_welcome,
    create_group,
    create_key_package,
    create_remove_proposal_for_self,
    create_update_proposal,
    export_sender_base_secret,
    get_dave_crypto_provider,
    join_from_welcome,
)


def test_get_dave_crypto_provider():
    """get_dave_crypto_provider returns a non-None crypto provider."""
    crypto = get_dave_crypto_provider()
    assert crypto is not None


def test_create_key_package_returns_tuple():
    """create_key_package returns (key_package_bytes, hpke_private, signing_der) with non-empty bytes."""
    kp_bytes, hpke_private, signing_der = create_key_package(123456789)
    assert isinstance(kp_bytes, bytes)
    assert isinstance(hpke_private, bytes)
    assert isinstance(signing_der, bytes)
    assert len(kp_bytes) > 0
    assert len(hpke_private) > 0
    assert len(signing_der) > 0


def test_create_group_single_member():
    """create_group with one key package yields group with member count 1."""
    kp_bytes, _, _ = create_key_package(111)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-group-id", kp_bytes, crypto)
    assert group is not None
    assert group._inner.get_member_count() == 1


def test_export_sender_base_secret_returns_16_bytes():
    kp_bytes, _, _ = create_key_package(222)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-export-group", kp_bytes, crypto)
    secret = export_sender_base_secret(group, 222)
    assert isinstance(secret, bytes)
    assert len(secret) == 16


def test_create_commit_and_welcome_returns_bytes_and_list():
    """create_commit_and_welcome returns (commit_bytes, list of welcome bytes)."""
    kp_bytes, hpke_private, signing_der = create_key_package(333)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-commit-group", kp_bytes, crypto)
    commit_bytes, welcome_list = create_commit_and_welcome(group, signing_der)
    assert isinstance(commit_bytes, bytes)
    assert len(commit_bytes) > 0
    assert isinstance(welcome_list, list)
    # No add proposals, so welcome list may be empty
    assert all(isinstance(w, bytes) for w in welcome_list)


def test_apply_commit_invalid_raises():
    kp_bytes, _, _ = create_key_package(444)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-apply-group", kp_bytes, crypto)
    with pytest.raises(InvalidCommitError, match="Failed to apply commit"):
        apply_commit(group, b"invalid_commit_bytes", 0)


def test_join_from_welcome_invalid_raises():
    """join_from_welcome with invalid welcome bytes raises an exception."""
    kp_bytes, hpke_private, _ = create_key_package(999)
    crypto = get_dave_crypto_provider()
    with pytest.raises(Exception):  # rfc9420 may raise various errors
        join_from_welcome(b"invalid_welcome_bytes", hpke_private, crypto)


def test_create_remove_proposal_for_self():
    kp_bytes, _, signing_der = create_key_package(888)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-remove-group", kp_bytes, crypto)
    proposal_bytes = create_remove_proposal_for_self(group, signing_der)
    assert isinstance(proposal_bytes, bytes)
    assert len(proposal_bytes) > 0


def test_create_update_proposal():
    """create_update_proposal returns non-empty serialized proposal bytes."""
    kp_bytes, _, signing_der = create_key_package(777)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-update-group", kp_bytes, crypto)
    proposal_bytes = create_update_proposal(group, signing_der, 777, crypto)
    assert isinstance(proposal_bytes, bytes)
    assert len(proposal_bytes) > 0
