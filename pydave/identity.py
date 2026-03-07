"""
Identity verification: pairwise fingerprint (scrypt) and displayable codes.
"""

# Salt for scrypt per protocol.md Verification Fingerprint
FINGERPRINT_SALT = bytes(
    [0x24, 0xCA, 0xB1, 0x7A, 0x7A, 0xF8, 0xEC, 0x2B, 0x82, 0xB4, 0x12, 0xB9, 0x2D, 0xAB, 0x19, 0x2E]
)
FINGERPRINT_VERSION = bytes((0x00, 0x00))  # V = 0x0000
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 2
SCRYPT_DKLEN = 64

# Pairwise: 64-byte output -> 45 digits (9 groups of 5)
PAIRWISE_DIGITS = 45
PAIRWISE_GROUP_SIZE = 5
# Epoch authenticator: 32-byte input -> 30 digits (6 groups of 5)
EPOCH_AUTH_DIGITS = 30
EPOCH_AUTH_GROUP_SIZE = 5


def displayable_code(data: bytes, total_digits: int, group_size: int = 5) -> str:
    """
    Encode byte array as displayable numeric code.
    For each group: next group_size bytes as big-endian int, modulo 10^group_size, zero-padded.
    total_digits must be a multiple of group_size; group_size < 8.
    """
    if total_digits % group_size != 0:
        raise ValueError("total_digits must be a multiple of group_size")
    if group_size >= 8:
        raise ValueError("group_size must be smaller than 8")
    num_groups = total_digits // group_size
    required_bytes = num_groups * group_size
    if len(data) < required_bytes:
        raise ValueError(f"Need at least {required_bytes} bytes, got {len(data)}")
    parts = []
    modulus = 10**group_size
    for i in range(num_groups):
        start = i * group_size
        chunk = data[start : start + group_size]
        # Big-endian: most significant byte first
        value = int.from_bytes(chunk, "big")
        code = value % modulus
        parts.append(str(code).zfill(group_size))
    return "".join(parts)


def generate_fingerprint(
    local_id: int,
    local_pub: bytes,
    remote_id: int,
    remote_pub: bytes,
) -> str:
    """
    Generate 45-digit pairwise verification fingerprint.
    bufA = V || PubA || Sa, bufB = V || PubB || Sb (Sa/Sb = big-endian 64-bit user IDs).
    Sort buffers lexicographically, scrypt(sorted_buffers, salt, N=16384, r=8, p=2, dkLen=64).
    Display: 9 groups of 5 digits.
    """
    sa = local_id.to_bytes(8, "big")
    sb = remote_id.to_bytes(8, "big")
    buf_a = FINGERPRINT_VERSION + local_pub + sa
    buf_b = FINGERPRINT_VERSION + remote_pub + sb
    sorted_buffers = b"".join(sorted([buf_a, buf_b]))
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    derived = Scrypt(
        length=SCRYPT_DKLEN,
        salt=FINGERPRINT_SALT,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(sorted_buffers)
    return displayable_code(derived, PAIRWISE_DIGITS, PAIRWISE_GROUP_SIZE)


def epoch_authenticator_display(epoch_authenticator_32_bytes: bytes) -> str:
    """Display epoch authenticator (32-byte exported secret) as 30-digit code."""
    if len(epoch_authenticator_32_bytes) < 30:
        raise ValueError("Epoch authenticator must be at least 30 bytes")
    return displayable_code(epoch_authenticator_32_bytes, EPOCH_AUTH_DIGITS, EPOCH_AUTH_GROUP_SIZE)
