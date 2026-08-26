"""DAVE media pipeline regressions: cryptor state, layered RTP, video ordering."""

from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sorrydave.crypto.cipher import DAVE_MAGIC
from sorrydave.crypto.ratchet import KeyRatchet
from sorrydave.exceptions import DecryptionError
from sorrydave.media.transform import FrameDecryptor, FrameEncryptor
from sorrydave.mls.opcodes import ExternalSenderPackage
from sorrydave.session import DaveSession

from tests._voice_imports import load_voice_module

OPUS_SILENCE = b"\xf8\xff\xfe"


def _esp() -> ExternalSenderPackage:
    return ExternalSenderPackage(
        sequence_number=0,
        signature_key=b"\xAA" * 32,
        credential_type=1,
        identity=b"\x00" * 8,
    )


def _ready_session(user_id: int = 7) -> DaveSession:
    session = DaveSession(local_user_id=user_id, protocol_version=1, channel_id=99)
    session.prepare_epoch(1)
    session.handle_external_sender_package(_esp())
    session._refresh_send_ratchet()
    session._refresh_receive_ratchets()
    session._current_epoch = 1
    return session


def _rtp_encrypt(header: bytes, payload: bytes, nonce_counter: int, key: bytes) -> bytes:
    nonce = bytearray(12)
    suffix = struct.pack(">I", nonce_counter)
    nonce[:4] = suffix
    ciphertext = AESGCM(key).encrypt(bytes(nonce), payload, header)
    return header + ciphertext + suffix


def _rtp_decrypt(packet: bytes, key: bytes) -> bytes:
    header = packet[:12]
    suffix = packet[-4:]
    ciphertext = packet[12:-4]
    nonce = bytearray(12)
    nonce[:4] = suffix
    return AESGCM(key).decrypt(bytes(nonce), ciphertext, header)


def _rtp_header(ssrc: int = 1, sequence: int = 1, timestamp: int = 0, marker: bool = False) -> bytes:
    header = bytearray(12)
    header[0] = 0x80
    header[1] = 0x78 | (0x80 if marker else 0)
    struct.pack_into(">H", header, 2, sequence)
    struct.pack_into(">I", header, 4, timestamp)
    struct.pack_into(">I", header, 8, ssrc)
    return bytes(header)


class TestCachedCryptorNonces:
    def test_session_encryptor_nonce_increments_across_frames(self):
        session = _ready_session()
        encryptor = session.get_encryptor()
        frames = [encryptor.encrypt(bytes([i]) * 8, "OPUS") for i in range(3)]
        assert session.get_encryptor() is encryptor
        assert encryptor._nonce == 3
        assert frames[0] != frames[1] != frames[2]
        for frame in frames:
            assert frame.endswith(DAVE_MAGIC)

    def test_replayed_dave_frame_is_rejected(self):
        secret = b"\x01" * 16
        encryptor = FrameEncryptor(1, KeyRatchet(secret))
        decryptor = FrameDecryptor(1, KeyRatchet(secret))
        protocol = encryptor.encrypt(b"\xAA" * 12, "OPUS")
        assert decryptor.decrypt(protocol) == b"\xAA" * 12
        with pytest.raises(DecryptionError, match="reuse"):
            decryptor.decrypt(protocol)

    def test_new_encryptor_per_packet_would_reuse_nonce_zero(self):
        secret = b"\x03" * 16
        first = FrameEncryptor(1, KeyRatchet(secret)).encrypt(b"\x11" * 8, "OPUS")
        second = FrameEncryptor(1, KeyRatchet(secret)).encrypt(b"\x22" * 8, "OPUS")
        decryptor = FrameDecryptor(1, KeyRatchet(secret))
        assert decryptor.decrypt(first) == b"\x11" * 8
        with pytest.raises(DecryptionError, match="reuse"):
            decryptor.decrypt(second)


class TestLayeredTransportThenDave:
    def test_transport_decrypt_reveals_dave_then_dave_restores_opus(self):
        session = _ready_session()
        opus = b"\x78" * 40
        dave_frame = session.get_encryptor().encrypt(opus, "OPUS")
        assert dave_frame.endswith(DAVE_MAGIC)
        key = b"\x42" * 32
        header = _rtp_header()
        packet = _rtp_encrypt(header, dave_frame, nonce_counter=3, key=key)
        transport_payload = _rtp_decrypt(packet, key)
        assert transport_payload == dave_frame
        decryptor = FrameDecryptor(session._local_user_id, session._send_ratchet)
        restored = decryptor.decrypt(transport_payload)
        assert restored == opus

    def test_transport_decrypt_does_not_consume_dave_nonce_state(self):
        session = _ready_session()
        key = b"\x11" * 32
        encryptor = session.get_encryptor()
        frames = [encryptor.encrypt(bytes([n]) * 10, "OPUS") for n in range(2)]
        packets = [
            _rtp_encrypt(_rtp_header(sequence=i + 1), frame, i + 1, key)
            for i, frame in enumerate(frames)
        ]
        decryptor = FrameDecryptor(session._local_user_id, session._send_ratchet)
        recovered = [decryptor.decrypt(_rtp_decrypt(packet, key)) for packet in packets]
        assert recovered == [b"\x00" * 10, b"\x01" * 10]

    def test_opus_silence_is_not_a_dave_protocol_frame(self):
        assert OPUS_SILENCE != DAVE_MAGIC
        assert not OPUS_SILENCE.endswith(DAVE_MAGIC)


class TestVideoDaveBeforePacketize:
    def test_split_h26x_keeps_dave_footer_on_last_nal(self):
        rtp = load_voice_module("rtp_packetizer")
        nal_a = bytes([0x67]) + b"sps-data"
        nal_b = bytes([0x65]) + b"idr-slice"
        footer = b"\x00" + DAVE_MAGIC
        frame = b"\x00\x00\x00\x01" + nal_a + b"\x00\x00\x00\x01" + nal_b + footer
        units = rtp.split_h26x_nalus(frame)
        assert units[0] == nal_a
        assert units[-1].endswith(footer)
        assert DAVE_MAGIC not in units[0]

    def test_packetize_then_depacketize_roundtrips_dave_video_frame(self):
        rtp = load_voice_module("rtp_packetizer")
        dep = load_voice_module("rtp_depacketizer")
        secret = b"\x09" * 16
        encryptor = FrameEncryptor(1, KeyRatchet(secret))
        decryptor = FrameDecryptor(1, KeyRatchet(secret))
        access_unit = b"\x00\x00\x00\x01" + bytes([0x67, 0x42]) + b"\xaa" * 20
        access_unit += b"\x00\x00\x00\x01" + bytes([0x65, 0x88]) + b"\xbb" * 80
        dave_frame = encryptor.encrypt(access_unit, "H264")
        assert dave_frame.endswith(DAVE_MAGIC)
        packetizer = rtp.make_packetizer("H264", ssrc=99, mtu=40)
        payloads = rtp.packetize_encoded_frame(packetizer, dave_frame, "H264")
        assert len(payloads) > 1
        depacketizer = dep.make_depacketizer("H264")
        rebuilt = None
        for index, payload in enumerate(payloads):
            rebuilt = depacketizer.push(payload, marker=index == len(payloads) - 1)
        assert rebuilt == dave_frame
        from sorrydave.media.codecs import transform_h26x_frame_for_encrypt

        expected, _ = transform_h26x_frame_for_encrypt(access_unit, h265=False)
        assert decryptor.decrypt(rebuilt) == expected

    def test_rtx_payload_is_cached_post_dave_fragment(self):
        rtp = load_voice_module("rtp_packetizer")
        secret = b"\x07" * 16
        encryptor = FrameEncryptor(1, KeyRatchet(secret))
        frame = b"\x00\x00\x00\x01" + bytes([0x65]) + b"\xcc" * 30
        dave_frame = encryptor.encrypt(frame, "H264")
        payloads = rtp.packetize_encoded_frame(
            rtp.make_packetizer("H264", ssrc=5, mtu=1200), dave_frame, "H264"
        )
        cached = list(payloads)
        assert cached == payloads
        assert encryptor._nonce == 1
