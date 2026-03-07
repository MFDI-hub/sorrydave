import pytest
from pydave.identity import displayable_code, generate_fingerprint, epoch_authenticator_display


def test_displayable_code():
    """
    displayable_code produces correct length and all-digit output for 30 bytes.
    """
    # 30 bytes -> 6 groups of 5 = 30 digits
    data = bytes(range(30))
    code = displayable_code(data, 30, 5)
    assert len(code) == 30
    assert code.isdigit()


def test_fingerprint_symmetric():
    """
    generate_fingerprint is symmetric: (A,B) and (B,A) produce same 45-digit code.
    """
    a_id, a_pub = 1, b"a" * 65
    b_id, b_pub = 2, b"b" * 65
    fp1 = generate_fingerprint(a_id, a_pub, b_id, b_pub)
    fp2 = generate_fingerprint(b_id, b_pub, a_id, a_pub)
    assert fp1 == fp2
    assert len(fp1) == 45


def test_epoch_authenticator():
    """epoch_authenticator_display produces 30-digit code from 32-byte input."""
    data = bytes(32)
    code = epoch_authenticator_display(data)
    assert len(code) == 30
