"""Tests for MLS group state (create_key_package, create_group, commit, export, etc.)."""

import pytest
from sorrydave.exceptions import InvalidCommitError
from sorrydave.mls.group_state import (
    apply_commit,
    apply_staged_commit,
    create_commit_and_welcome,
    create_group,
    create_key_package,
    create_remove_proposal_for_self,
    create_update_proposal,
    export_sender_base_secret,
    get_dave_crypto_provider,
    join_from_welcome,
    process_proposal,
    stage_commit_and_welcome,
)


def test_get_dave_crypto_provider():
    """get_dave_crypto_provider returns a non-None crypto provider."""
    crypto = get_dave_crypto_provider()
    assert crypto is not None


def test_create_key_package_returns_tuple():
    """create_key_package returns (key_package_bytes, hpke_private, signing_der) with non-empty bytes."""
    kp_bytes, hpke_private, signing_der, enc_private = create_key_package(123456789)
    assert isinstance(kp_bytes, bytes)
    assert isinstance(hpke_private, bytes)
    assert isinstance(signing_der, bytes)
    assert isinstance(enc_private, bytes)
    assert len(kp_bytes) > 0
    assert len(hpke_private) > 0
    assert len(signing_der) > 0
    assert len(enc_private) > 0
    assert hpke_private != enc_private


def test_create_key_package_reuses_persistent_signing_key():
    from sorrydave.mls.group_state import _p256_public_from_der
    from sorrydave.persistent_keys import generate_p256_keypair

    pub, priv = generate_p256_keypair()
    kp_bytes, _hpke, signing_der, _enc = create_key_package(99, signing_key_der=priv)
    assert signing_der == priv
    assert _p256_public_from_der(signing_der) == pub
    assert len(kp_bytes) > 0


def test_create_group_single_member():
    """create_group with one key package yields session with member count 1."""
    kp_bytes, *_ = create_key_package(111)
    crypto = get_dave_crypto_provider()
    session = create_group(b"test-group-id", kp_bytes, crypto)
    assert session is not None
    assert session.member_count == 1


def test_export_sender_base_secret_returns_16_bytes():
    kp_bytes, *_ = create_key_package(222)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-export-group", kp_bytes, crypto)
    secret = export_sender_base_secret(group, 222)
    assert isinstance(secret, bytes)
    assert len(secret) == 16


def test_create_commit_and_welcome_returns_bytes_and_list():
    """create_commit_and_welcome returns (commit_bytes, list of welcome bytes)."""
    kp_bytes, hpke_private, signing_der, _enc = create_key_package(333)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-commit-group", kp_bytes, crypto)
    commit_bytes, welcome_list = create_commit_and_welcome(group, signing_der)
    assert isinstance(commit_bytes, bytes)
    assert len(commit_bytes) > 0
    assert isinstance(welcome_list, list)
    # No add proposals, so welcome list may be empty
    assert all(isinstance(w, bytes) for w in welcome_list)


def test_staged_commit_does_not_advance_epoch_until_applied():
    from rfc9420.group.mls_group.processing import MlsGroupState

    kp_bytes, _, signing_der, _ = create_key_package(334)
    group = create_group(b"test-staged-commit-group", kp_bytes, get_dave_crypto_provider())
    epoch_before = group.epoch

    commit_bytes, welcomes, staged = stage_commit_and_welcome(group, signing_der)

    assert commit_bytes
    assert welcomes == []
    assert group.epoch == epoch_before
    assert group._group._inner._state == MlsGroupState.OPERATIONAL
    assert group._group._inner._commit_pending is False

    apply_staged_commit(group, staged)
    assert group.epoch == epoch_before + 1


def test_apply_commit_invalid_raises():
    kp_bytes, *_ = create_key_package(444)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-apply-group", kp_bytes, crypto)
    with pytest.raises(InvalidCommitError, match="Failed to apply commit"):
        apply_commit(group, b"invalid_commit_bytes", 0)


def test_join_from_welcome_invalid_raises():
    """join_from_welcome with invalid welcome bytes raises an exception."""
    kp_bytes, hpke_private, *_ = create_key_package(999)
    crypto = get_dave_crypto_provider()
    with pytest.raises(Exception):  # noqa: B017 rfc9420 may raise various errors
        join_from_welcome(b"invalid_welcome_bytes", hpke_private, crypto)


def test_create_remove_proposal_for_self():
    kp_bytes, _, signing_der, _ = create_key_package(888)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-remove-group", kp_bytes, crypto)
    proposal_bytes = create_remove_proposal_for_self(group, signing_der)
    assert isinstance(proposal_bytes, bytes)
    assert len(proposal_bytes) > 0


def test_create_update_proposal():
    """create_update_proposal returns non-empty serialized proposal bytes."""
    kp_bytes, _, signing_der, _ = create_key_package(777)
    crypto = get_dave_crypto_provider()
    group = create_group(b"test-update-group", kp_bytes, crypto)
    proposal_bytes = create_update_proposal(group, signing_der, 777, crypto)
    assert isinstance(proposal_bytes, bytes)
    assert len(proposal_bytes) > 0


def test_two_member_add_welcome_export():
    """Add a second member, join via Welcome, and match exporter secrets (rfc9420 1.2.0)."""
    from rfc9420.messages.key_packages import KeyPackage

    crypto = get_dave_crypto_provider()
    kp_a, _init_a, sig_a, _enc_a = create_key_package(1, crypto)
    kp_b, init_b, _sig_b, enc_b = create_key_package(2, crypto)
    from sorrydave.mls.group_state import _rfc9420_dave_commit_interop

    alice = create_group(
        b"two-member-group",
        kp_a,
        crypto,
        external_sender_signature_key=b"\xaa" * 65,
        external_sender_credential_type=1,
        external_sender_identity=b"\x00" * 8,
    )
    with _rfc9420_dave_commit_interop():
        hs = alice.add_member(KeyPackage.deserialize(kp_b), sig_a)
    alice.process_proposal(hs, alice.own_leaf_index)
    _commit_bytes, welcomes = create_commit_and_welcome(alice, sig_a)
    assert welcomes
    bob = join_from_welcome(
        welcomes[0],
        init_b,
        crypto,
        encryption_private_key=enc_b,
        key_package=kp_b,
    )
    assert alice.member_count == 2
    assert bob.member_count == 2
    assert export_sender_base_secret(alice, 1) == export_sender_base_secret(bob, 1)
    assert export_sender_base_secret(alice, 2) == export_sender_base_secret(bob, 2)


def test_remove_then_readd_same_key_package_can_share_one_commit():
    """Discord sends replacement Remove/Add proposals in separate op27 messages."""
    from rfc9420.messages.key_packages import KeyPackage

    crypto = get_dave_crypto_provider()
    kp_a, _, sig_a, _ = create_key_package(10, crypto)
    kp_b, _, _, _ = create_key_package(20, crypto)
    group = create_group(b"replace-member-group", kp_a, crypto)

    initial_add = group.add_member(KeyPackage.deserialize(kp_b), sig_a)
    process_proposal(group, initial_add, sender_leaf_index=0)
    create_commit_and_welcome(group, sig_a)
    assert group.member_count == 2

    remove = group.remove_member(1, sig_a)
    process_proposal(group, remove, sender_leaf_index=0)
    _, _, _remove_candidate = stage_commit_and_welcome(group, sig_a)
    replacement_add = group.add_member(KeyPackage.deserialize(kp_b), sig_a)
    process_proposal(group, replacement_add, sender_leaf_index=0)

    _, welcomes, staged = stage_commit_and_welcome(group, sig_a)
    assert welcomes
    apply_staged_commit(group, staged)
    assert group.member_count == 2
