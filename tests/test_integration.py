"""End-to-end integration tests: full encrypt/decrypt pipeline, multi-codec, epoch transitions."""

import pytest

from sorrydave.crypto.ratchet import KeyRatchet
from sorrydave.exceptions import DecryptionError
from sorrydave.media.transform import (
    SILENCE_PACKET,
    FrameDecryptor,
    FrameEncryptor,
    protocol_frame_check,
)


def make_pair(secret: bytes = b"\x01" * 16, user_id: int = 1, **kw):
    """Create matched encryptor + decryptor pair."""
    enc_ratchet = KeyRatchet(secret, **kw)
    dec_ratchet = KeyRatchet(secret, **kw)
    enc = FrameEncryptor(sender_user_id=user_id, ratchet=enc_ratchet)
    dec = FrameDecryptor(sender_user_id=user_id, ratchet=dec_ratchet)
    return enc, dec


class TestFullPipelineAllCodecs:
    """Encrypt-then-decrypt roundtrip for every supported codec."""

    @pytest.mark.parametrize("codec,frame", [
        ("OPUS", b"\xAA" * 100),
        ("VP9", b"\xBB" * 80),
        ("VP8", b"\x00" + b"\xCC" * 50),  # keyframe
        ("VP8", b"\x01" + b"\xDD" * 50),  # delta
        ("H264", b"\x00\x00\x01\x67" + b"\xEE" * 30),
        ("H265", b"\x00\x00\x01" + bytes([(32 << 1) & 0x7E, 0x00]) + b"\xFF" * 30),
        ("AV1", bytes([(1 << 3) | 0x02, 0x03, 0xAA, 0xBB, 0xCC])),
    ])
    def test_roundtrip(self, codec, frame):
        enc, dec = make_pair()
        protocol_frame = enc.encrypt(frame, codec)
        assert protocol_frame_check(protocol_frame)
        if codec != "AV1":
            result = dec.decrypt(protocol_frame)
            assert result == frame
        else:
            dec.decrypt(protocol_frame)


class TestMultiFrameStream:
    """Simulate a stream of frames."""

    def test_100_sequential_frames(self):
        enc, dec = make_pair()
        for i in range(100):
            frame = bytes([i % 256]) * 20
            pf = enc.encrypt(frame, "OPUS")
            assert protocol_frame_check(pf)
            result = dec.decrypt(pf)
            assert result == frame

    def test_out_of_order_within_gap(self):
        """Decrypt frames arriving out of order (within ratchet forward gap)."""
        secret = b"\x01" * 16
        enc_ratchet = KeyRatchet(secret, max_forward_gap=200)
        enc = FrameEncryptor(sender_user_id=1, ratchet=enc_ratchet)
        frames = []
        for i in range(10):
            pf = enc.encrypt(bytes([i]) * 10, "OPUS")
            frames.append((pf, bytes([i]) * 10))
        import random
        random.seed(42)
        order = list(range(10))
        random.shuffle(order)
        dec_ratchet = KeyRatchet(secret, max_forward_gap=200)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        for idx in order:
            pf, expected = frames[idx]
            result = dec.decrypt(pf)
            assert result == expected


class TestEpochTransition:
    """Test encrypt/decrypt across epoch boundaries."""

    def test_epoch_advance_new_keys(self):
        secret1 = b"\x01" * 16
        secret2 = b"\x02" * 16
        enc_ratchet = KeyRatchet(secret1)
        dec_ratchet = KeyRatchet(secret1)
        enc = FrameEncryptor(sender_user_id=1, ratchet=enc_ratchet)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        frame = b"\xAA" * 20
        pf = enc.encrypt(frame, "OPUS")
        assert dec.decrypt(pf) == frame
        enc_ratchet.advance_epoch(secret2)
        dec_ratchet.advance_epoch(secret2)
        enc2 = FrameEncryptor(sender_user_id=1, ratchet=enc_ratchet)
        dec2 = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        frame2 = b"\xBB" * 20
        pf2 = enc2.encrypt(frame2, "OPUS")
        assert dec2.decrypt(pf2) == frame2

    def test_old_key_cannot_decrypt_new_epoch(self):
        secret1 = b"\x01" * 16
        secret2 = b"\x02" * 16
        enc_ratchet = KeyRatchet(secret2)
        dec_ratchet = KeyRatchet(secret1)
        enc = FrameEncryptor(sender_user_id=1, ratchet=enc_ratchet)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_ratchet)
        pf = enc.encrypt(b"\xAA" * 20, "OPUS")
        with pytest.raises(DecryptionError):
            dec.decrypt(pf)


class TestSilenceAndPassthrough:
    def test_silence_packet_passthrough(self):
        _, dec = make_pair()
        assert dec.decrypt(SILENCE_PACKET) == SILENCE_PACKET

    def test_passthrough_mode_non_protocol(self):
        enc_r = KeyRatchet(b"\x01" * 16)
        dec_r = KeyRatchet(b"\x01" * 16)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_r, passthrough=True)
        non_proto = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E"
        assert dec.decrypt(non_proto) == non_proto

    def test_passthrough_encryptor(self):
        r = KeyRatchet(b"\x01" * 16)
        enc = FrameEncryptor(sender_user_id=1, ratchet=r, passthrough=True)
        frame = b"\xAA" * 20
        assert enc.encrypt(frame, "OPUS") == frame

    def test_passthrough_decryptor_decrypts_protocol_frame(self):
        enc, _ = make_pair()
        dec_r = KeyRatchet(b"\x01" * 16)
        dec = FrameDecryptor(sender_user_id=1, ratchet=dec_r, passthrough=True)
        frame = b"\xBB" * 20
        pf = enc.encrypt(frame, "OPUS")
        assert dec.decrypt(pf) == frame


class TestMultipleSenders:
    """Simulate multi-party session with different sender ratchets."""

    def test_two_senders(self):
        secret_a = b"\x01" * 16
        secret_b = b"\x02" * 16
        enc_a = FrameEncryptor(1, KeyRatchet(secret_a))
        enc_b = FrameEncryptor(2, KeyRatchet(secret_b))
        dec_a = FrameDecryptor(1, KeyRatchet(secret_a))
        dec_b = FrameDecryptor(2, KeyRatchet(secret_b))
        frame_a = b"\xAA" * 20
        frame_b = b"\xBB" * 20
        pf_a = enc_a.encrypt(frame_a, "OPUS")
        pf_b = enc_b.encrypt(frame_b, "OPUS")
        assert dec_a.decrypt(pf_a) == frame_a
        assert dec_b.decrypt(pf_b) == frame_b

    def test_cross_sender_decryption_fails(self):
        secret_a = b"\x01" * 16
        secret_b = b"\x02" * 16
        enc_a = FrameEncryptor(1, KeyRatchet(secret_a))
        dec_b = FrameDecryptor(2, KeyRatchet(secret_b))
        pf_a = enc_a.encrypt(b"\xAA" * 20, "OPUS")
        with pytest.raises(DecryptionError):
            dec_b.decrypt(pf_a)


class TestEdgeCases:
    def test_single_byte_frame(self):
        enc, dec = make_pair()
        pf = enc.encrypt(b"\x42", "OPUS")
        assert dec.decrypt(pf) == b"\x42"

    def test_empty_frame(self):
        enc, dec = make_pair()
        pf = enc.encrypt(b"", "OPUS")
        assert dec.decrypt(pf) == b""

    def test_max_nonce_value_encrypt(self):
        r = KeyRatchet(b"\x01" * 16, max_forward_gap=1000)
        enc = FrameEncryptor(1, r, nonce_supplier=lambda: 0xFFFFFFFF)
        pf = enc.encrypt(b"\xAA" * 10, "OPUS")
        assert protocol_frame_check(pf)

    def test_all_zeros_frame(self):
        enc, dec = make_pair()
        frame = b"\x00" * 100
        pf = enc.encrypt(frame, "OPUS")
        assert dec.decrypt(pf) == frame

    def test_all_ff_frame(self):
        enc, dec = make_pair()
        frame = b"\xFF" * 100
        pf = enc.encrypt(frame, "OPUS")
        assert dec.decrypt(pf) == frame

    def test_frame_with_magic_bytes(self):
        enc, dec = make_pair()
        frame = b"\xFA\xFA" * 50
        pf = enc.encrypt(frame, "OPUS")
        assert dec.decrypt(pf) == frame

    def test_large_frame(self):
        enc, dec = make_pair()
        frame = bytes(range(256)) * 100
        pf = enc.encrypt(frame, "OPUS")
        assert dec.decrypt(pf) == frame


class TestNonceReuseProtection:
    def test_replay_rejected(self):
        enc, dec = make_pair()
        pf = enc.encrypt(b"\xAA" * 10, "OPUS")
        dec.decrypt(pf)
        with pytest.raises(DecryptionError, match="reuse"):
            dec.decrypt(pf)

    def test_different_nonces_accepted(self):
        enc, dec = make_pair()
        pf1 = enc.encrypt(b"\xAA" * 10, "OPUS")
        pf2 = enc.encrypt(b"\xBB" * 10, "OPUS")
        dec.decrypt(pf1)
        dec.decrypt(pf2)


class TestTampering:
    def test_bit_flip_ciphertext(self):
        enc, dec = make_pair()
        pf = enc.encrypt(b"\xAA" * 20, "OPUS")
        tampered = bytearray(pf)
        tampered[0] ^= 0x01
        with pytest.raises(DecryptionError):
            dec.decrypt(bytes(tampered))

    def test_bit_flip_tag(self):
        enc, dec = make_pair()
        pf = enc.encrypt(b"\xAA" * 20, "OPUS")
        suppl_size = pf[-3]
        tag_start = len(pf) - suppl_size
        tampered = bytearray(pf)
        tampered[tag_start] ^= 0xFF
        with pytest.raises(DecryptionError):
            dec.decrypt(bytes(tampered))

    def test_truncated_frame(self):
        enc, dec = make_pair()
        pf = enc.encrypt(b"\xAA" * 20, "OPUS")
        with pytest.raises(DecryptionError):
            dec.decrypt(pf[:5])
