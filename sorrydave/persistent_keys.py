"""
Persistent signature key storage and Discord self-signature for voice public key upload.

Provides key storage (save/load from path) and construction of the MLS-style
self-signature required for PUT /voice/public-keys (protocol.md §Persistent Public Key Upload).
No I/O to Discord API; the caller builds the HTTP request from the returned payload.
"""

from dataclasses import dataclass
from typing import Optional

# MLS 1.0 Discord Self Signature label: 0x1c (varint length 28) + 28 bytes per protocol.md
DISCORD_SELF_SIGNATURE_LABEL = b"\x1cMLS 1.0 DiscordSelfSignature"


def _mls_varint(x: int) -> bytes:
    """RFC 9420 variable-length integer encoding for MLS signable data."""
    if x < 0x40:
        return bytes([x])
    if x < 0x4000:
        return (x | 0x4000).to_bytes(2, "big")
    if x <= 0x3FFFFFFF:
        return (x | 0x80000000).to_bytes(4, "big")
    raise ValueError("integer too large for MLS varint")


def build_discord_self_signature_signable_data(
    client_auth_session_id: str,
    public_key: bytes,
) -> bytes:
    """
    Build the signable data for Discord voice public key self-signature.

    Per protocol.md: mls_label (0x1c + 28 bytes) + mls_varint(len(full_context)) + full_context,
    where full_context = application_signature_label + public_key and
    application_signature_label = ascii(clientAuthSessionID + ':').

    Args:
        client_auth_session_id (str): Session ID from Discord API READY payload.
        public_key (bytes): P256 public key (X9.62 format, same as used for upload).

    Returns:
        bytes: Data to be signed with ECDSA P256 SHA256.
    """
    application_signature_label = (client_auth_session_id + ":").encode("ascii")
    full_context = application_signature_label + public_key
    varint_prepend = _mls_varint(len(full_context))
    return DISCORD_SELF_SIGNATURE_LABEL + varint_prepend + full_context


def sign_discord_self_signature(
    signable_data: bytes,
    private_key_der: bytes,
) -> bytes:
    """
    Sign the Discord self-signature signable data with ECDSA P256 SHA256.

    Args:
        signable_data (bytes): Output of build_discord_self_signature_signable_data.
        private_key_der (bytes): P256 private key in DER (PKCS#8) form.

    Returns:
        bytes: ECDSA signature (raw r||s or DER; caller uses for upload).
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = serialization.load_der_private_key(
        private_key_der,
        password=None,
    )
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Key must be an EC private key")
    return key.sign(signable_data, ec.ECDSA(hashes.SHA256()))


def build_voice_public_keys_upload_payload(
    client_auth_session_id: str,
    public_key: bytes,
    private_key_der: bytes,
    key_version: int,
) -> "VoicePublicKeysPayload":
    """
    Build the payload for PUT /voice/public-keys.

    Produces public key, key version, and MLS-style self-signature. The caller
    must encode byte fields (e.g. base64) and send the request; this module
    does not perform I/O.

    Args:
        client_auth_session_id (str): Session ID from Discord API READY.
        public_key (bytes): P256 public key (X9.62, compressed or uncompressed).
        private_key_der (bytes): P256 private key (PKCS#8 DER).
        key_version (int): Key version (e.g. 1).

    Returns:
        VoicePublicKeysPayload: public_key, key_version, signature for the API.
    """
    signable = build_discord_self_signature_signable_data(client_auth_session_id, public_key)
    signature = sign_discord_self_signature(signable, private_key_der)
    return VoicePublicKeysPayload(
        public_key=public_key,
        key_version=key_version,
        signature=signature,
    )


def save_persistent_signature_key(storage_path: str, private_key_der: bytes) -> None:
    """
    Save a persistent signature private key to disk.

    Writes PEM (PKCS#8) so keys are standard and can be loaded by other tools.
    Caller is responsible for choosing a secure path (IdentityConfig.storage_path).

    Args:
        storage_path (str): File path to write.
        private_key_der (bytes): P256 private key (PKCS#8 DER).
    """
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_der_private_key(private_key_der, password=None)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(storage_path, "wb") as f:
        f.write(pem)


def load_persistent_signature_key(storage_path: str) -> Optional[bytes]:
    """
    Load a persistent signature private key from disk.

    Reads PEM (PKCS#8). Returns None if the file does not exist or cannot be read.

    Args:
        storage_path (str): File path to read.

    Returns:
        Optional[bytes]: P256 private key in DER (PKCS#8), or None if not found.
    """
    import os

    if not os.path.isfile(storage_path):
        return None
    try:
        with open(storage_path, "rb") as f:
            pem = f.read()
    except OSError:
        return None
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem, password=None)
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_p256_keypair() -> tuple[bytes, bytes]:
    """
    Generate a new P256 keypair for use as persistent or ephemeral signature key.

    Returns:
        tuple[bytes, bytes]: (public_key_x962, private_key_der). Public key is
        uncompressed X9.62 (0x04 || x || y); private key is PKCS#8 DER.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if public_key[0] != 0x04:
        public_key = b"\x04" + public_key
    return (public_key, private_key_der)


@dataclass(frozen=True)
class VoicePublicKeysPayload:
    """
    Payload for PUT /voice/public-keys.

    Attributes:
        public_key (bytes): P256 public key (X9.62).
        key_version (int): Key version.
        signature (bytes): ECDSA self-signature over the protocol signable data.
    """

    public_key: bytes
    key_version: int
    signature: bytes
