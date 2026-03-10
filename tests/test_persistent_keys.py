"""Tests for sorrydave.persistent_keys: keygen, signing, save/load, upload payload."""

from __future__ import annotations

import os
import tempfile

import pytest

from sorrydave.persistent_keys import (
    DISCORD_SELF_SIGNATURE_LABEL,
    VoicePublicKeysPayload,
    build_discord_self_signature_signable_data,
    build_voice_public_keys_upload_payload,
    generate_p256_keypair,
    load_persistent_signature_key,
    save_persistent_signature_key,
    sign_discord_self_signature,
)


class TestGenerateP256Keypair:
    def test_returns_tuple(self):
        pub, priv = generate_p256_keypair()
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_public_key_is_uncompressed_x962(self):
        pub, _ = generate_p256_keypair()
        assert pub[0] == 0x04
        assert len(pub) == 65  # 1 prefix + 32 x + 32 y

    def test_private_key_is_der(self):
        _, priv = generate_p256_keypair()
        assert len(priv) > 100
        # DER PKCS#8 starts with SEQUENCE tag 0x30
        assert priv[0] == 0x30

    def test_two_keypairs_are_different(self):
        pub1, priv1 = generate_p256_keypair()
        pub2, priv2 = generate_p256_keypair()
        assert pub1 != pub2
        assert priv1 != priv2

    def test_private_key_can_reload(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        _, priv = generate_p256_keypair()
        key = serialization.load_der_private_key(priv, password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)


class TestBuildSignableData:
    def test_contains_label(self):
        data = build_discord_self_signature_signable_data("session123", b"\x04" + b"\x00" * 64)
        assert DISCORD_SELF_SIGNATURE_LABEL in data

    def test_contains_session_id(self):
        data = build_discord_self_signature_signable_data("my_session_xyz", b"\x04" + b"\x00" * 64)
        assert b"my_session_xyz:" in data

    def test_contains_public_key(self):
        pub = b"\x04" + bytes(range(64))
        data = build_discord_self_signature_signable_data("sess", pub)
        assert pub in data

    def test_format_structure(self):
        pub = b"\x04" + b"\xaa" * 64
        data = build_discord_self_signature_signable_data("S", pub)
        # mls_label + varint(len(full_context)) + "S:" + pub
        assert data.startswith(DISCORD_SELF_SIGNATURE_LABEL)
        remaining = data[len(DISCORD_SELF_SIGNATURE_LABEL):]
        # full_context = "S:" (2 bytes) + pub (65 bytes) = 67 bytes
        # varint for 67 = 0x43 (single byte, < 0x40 is 1-byte... 67 > 63 so 2-byte)
        # Actually 67 >= 0x40 so it's a 2-byte varint
        full_context = b"S:" + pub
        assert full_context in remaining

    def test_different_sessions_different_data(self):
        pub = b"\x04" + b"\xaa" * 64
        d1 = build_discord_self_signature_signable_data("session_a", pub)
        d2 = build_discord_self_signature_signable_data("session_b", pub)
        assert d1 != d2


class TestSignDiscordSelfSignature:
    def test_sign_returns_bytes(self):
        pub, priv = generate_p256_keypair()
        signable = build_discord_self_signature_signable_data("test_session", pub)
        sig = sign_discord_self_signature(signable, priv)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_signature_is_valid_ecdsa(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        pub, priv = generate_p256_keypair()
        signable = build_discord_self_signature_signable_data("verify_session", pub)
        sig = sign_discord_self_signature(signable, priv)

        priv_key = serialization.load_der_private_key(priv, password=None)
        pub_key = priv_key.public_key()
        # Should not raise
        pub_key.verify(sig, signable, ec.ECDSA(hashes.SHA256()))

    def test_signature_fails_with_wrong_data(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature

        pub, priv = generate_p256_keypair()
        signable = build_discord_self_signature_signable_data("sess", pub)
        sig = sign_discord_self_signature(signable, priv)

        priv_key = serialization.load_der_private_key(priv, password=None)
        pub_key = priv_key.public_key()
        with pytest.raises(InvalidSignature):
            pub_key.verify(sig, b"tampered data", ec.ECDSA(hashes.SHA256()))

    def test_different_keys_different_signatures(self):
        pub1, priv1 = generate_p256_keypair()
        pub2, priv2 = generate_p256_keypair()
        signable = build_discord_self_signature_signable_data("same_session", pub1)
        sig1 = sign_discord_self_signature(signable, priv1)
        sig2 = sign_discord_self_signature(signable, priv2)
        # ECDSA uses random k, so signatures differ even with same key,
        # but definitely differ with different keys
        assert sig1 != sig2

    def test_non_ec_key_raises(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_der = rsa_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(ValueError, match="EC private key"):
            sign_discord_self_signature(b"data", rsa_der)


class TestBuildVoicePublicKeysUploadPayload:
    def test_returns_payload_dataclass(self):
        pub, priv = generate_p256_keypair()
        payload = build_voice_public_keys_upload_payload("sess", pub, priv, key_version=1)
        assert isinstance(payload, VoicePublicKeysPayload)
        assert payload.public_key == pub
        assert payload.key_version == 1
        assert isinstance(payload.signature, bytes)
        assert len(payload.signature) > 0

    def test_signature_validates(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        pub, priv = generate_p256_keypair()
        payload = build_voice_public_keys_upload_payload("my_sess", pub, priv, key_version=1)

        signable = build_discord_self_signature_signable_data("my_sess", pub)
        priv_key = serialization.load_der_private_key(priv, password=None)
        pub_key = priv_key.public_key()
        pub_key.verify(payload.signature, signable, ec.ECDSA(hashes.SHA256()))

    def test_frozen_dataclass(self):
        pub, priv = generate_p256_keypair()
        payload = build_voice_public_keys_upload_payload("s", pub, priv, key_version=1)
        with pytest.raises(AttributeError):
            payload.key_version = 2


class TestSaveLoadPersistentKey:
    def test_save_and_load_roundtrip(self):
        _, priv = generate_p256_keypair()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            save_persistent_signature_key(path, priv)
            loaded = load_persistent_signature_key(path)
            assert loaded is not None
            assert loaded == priv
        finally:
            os.unlink(path)

    def test_saved_file_is_pem(self):
        _, priv = generate_p256_keypair()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            save_persistent_signature_key(path, priv)
            with open(path, "rb") as f:
                content = f.read()
            assert b"BEGIN PRIVATE KEY" in content
            assert b"END PRIVATE KEY" in content
        finally:
            os.unlink(path)

    def test_load_nonexistent_returns_none(self):
        result = load_persistent_signature_key("/nonexistent/path/key.pem")
        assert result is None

    def test_loaded_key_can_sign(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        pub, priv = generate_p256_keypair()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            save_persistent_signature_key(path, priv)
            loaded = load_persistent_signature_key(path)
            key = serialization.load_der_private_key(loaded, password=None)
            sig = key.sign(b"test data", ec.ECDSA(hashes.SHA256()))
            assert isinstance(sig, bytes)
        finally:
            os.unlink(path)

    def test_multiple_save_overwrites(self):
        _, priv1 = generate_p256_keypair()
        _, priv2 = generate_p256_keypair()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            save_persistent_signature_key(path, priv1)
            save_persistent_signature_key(path, priv2)
            loaded = load_persistent_signature_key(path)
            assert loaded == priv2
        finally:
            os.unlink(path)
