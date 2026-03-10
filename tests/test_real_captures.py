"""
Tests using real captured Discord voice gateway data.

Uses the actual hex-encoded and base64-encoded binary messages from idk and udp.txt
to verify that sorrydave correctly parses DAVE MLS binary opcodes and JSON gateway
messages from real Discord sessions.
"""

from __future__ import annotations

import base64
import orjson
import struct

import pytest

from sorrydave.mls.opcodes import (
    ExternalSenderPackage,
    OPCODE_EXTERNAL_SENDER_PACKAGE,
    OPCODE_KEY_PACKAGE,
    parse_external_sender_package,
    parse_select_protocol_ack,
)

# ── Real captured binary payloads ──
# From idk (hex-encoded, DAVE v1 session):
# Line 17: opcode 25 (external sender package)
HEX_OP25_IDK = (
    "00011940410469e407ca0fe416ad2df8e65c1ba206c70c57c4a058ddf1e96f453d"
    "e9586faef506c1209fa27d93278f07da704cb93502f89d679540cb41c2547c4217"
    "58ef83b700010100"
)
# Line 19: opcode 26 (key package)
HEX_OP26_IDK = (
    "1a00010002404104fbc3ed09c3bb245758b37d69358ffb96485ca1b015c73c2e35"
    "f15e4a8529f2a915de9fb8f2241d67372276e2350d834782a61df62aeb28aa0c30"
    "430f751a06f44041043678c5ca8a34b2c7a2add0d2bf9237d562045817b59ffcd8"
    "869a04c14f6f3cc7cba1cfa504f49352823c8654ebd5b23566737b9e44cc27e217"
    "a986b8f5b69837404104a227ce7e6f2717c1a3c30ef0923b497c60107767ed5928"
    "0a06745077bca6ac4d75f410fa708a3f1be3d694515c0b682efe108e67795ab7db"
    "c929ec250e19984d000108038db7497640000b0200010200020000020001010000"
    "000000000000ffffffffffffffff00404730450220297f1c838f02ba36e2741b47"
    "616b88015d73bda971058de045fd17709fb13c80022100e7cab8449a9cadb78e1e"
    "67b784ebcb0f066002e09c658230c4e83ba5a96576960040483046022100a14ff6"
    "50b153eef4ee0aaf2953799b362388d7e6434cba8f5876f4fa49845934022100c1"
    "a019e7ece94781c52e43226ef124ae6a1c9dffe0d395cc1ba30dcca8434cb7"
)

# From udp.txt (base64-encoded, DAVE v1 session):
# Line 40: opcode 25 (external sender package)
B64_OP25_UDP = "AAEZQEEEt8YIK3f/iy+bUxPV8VW4FW//FRyTxh6CCqLFfaOudbRs2cPfbH1XToX552ToE8eChpbOj9P/vHZfoyym3HCPoAABAQA="
# Line 42: opcode 26 (key package)
B64_OP26_UDP = (
    "GgABAAJAQQScHOEEhxcHPkr3dpceQQDl0+Cq4JsIVdliguQGEeiDXhoNZLvsvcnS"
    "IaDoYDJGSwEXJcGSnf//3csTnxE6UtEMQEEEtveGWT/cZb+l9+oKBybOUNEunEay"
    "tOLgcQK6mg09zjtVzT0p6c6bGtBlXfG7O2844bpIo+Ah6JtKERt2gZ8biEBBBNSg"
    "kB2WRT42/eFakwO++cSfm18jQ4NHCgYKbLlHFCYfeiIzhBJ44btrsUhf2Hhgw4cW"
    "bfS25WrLICn0K/UAQnoAAQgDjbdJdkAACwIAAQIAAgAAAgABAQAAAAAAAAAA////"
    "////////AEBHMEUCIHiAC4oOE1NIjZKNoY7t9LMDoaMK4k7M79/oalZrFhb1AiEA"
    "9uH2z4JahpZiFQsJbqTwAcDlomu3qjX6CTbn6v1b6q4AQEcwRQIgECp4x9eVBFQX"
    "ZTnT84iohyAmYOYUEjEQUEtoe3F7bzQCIQCQIXC9ALCxENPOkt0tVKlPRs5z2FqA"
    "gqgwKUrhecE1iQ=="
)

# Real JSON messages from idk:
JSON_OP0_IDK = '{"op":0,"d":{"server_id":"1043272195868217364","channel_id":"1043272195868217368","user_id":"256062279974387723","session_id":"bd798a4dd3a1b3209a1b764cc7e73798","token":"8f78a843b2b3bc12","max_dave_protocol_version":1,"video":true,"streams":[{"type":"video","rid":"100","quality":100},{"type":"video","rid":"50","quality":50}]}}'
JSON_OP4_IDK = '{"op":4,"d":{"video_codec":"H265","secure_frames_version":1,"secret_key":[254,118,6,145,6,5,71,9,200,63,91,105,46,188,124,39,34,0,41,49,173,135,77,7,104,74,50,97,125,113,180,145],"mode":"aead_aes256_gcm_rtpsize","media_session_id":"f0354805660f56a5b301be462004c9de","dave_protocol_version":1,"audio_codec":"opus"}}'
JSON_OP2_IDK = '{"op":2,"d":{"streams":[{"type":"video","ssrc":7277,"rtx_ssrc":7278,"rid":"50","quality":50,"active":false},{"type":"video","ssrc":7279,"rtx_ssrc":7280,"rid":"100","quality":100,"active":false}],"ssrc":7276,"port":19311,"modes":["aead_aes256_gcm_rtpsize","aead_xchacha20_poly1305_rtpsize"],"ip":"104.29.151.192","experiments":["fixed_keyframe_interval"]}}'


class TestParseRealOp25HexFromIdk:
    """Parse real opcode 25 (external sender package) from idk capture (hex-encoded)."""

    def test_decode_hex(self):
        raw = bytes.fromhex(HEX_OP25_IDK)
        assert len(raw) == 74

    def test_parse_opcode_25(self):
        raw = bytes.fromhex(HEX_OP25_IDK)
        pkg = parse_external_sender_package(raw)
        assert isinstance(pkg, ExternalSenderPackage)

    def test_sequence_number(self):
        raw = bytes.fromhex(HEX_OP25_IDK)
        pkg = parse_external_sender_package(raw)
        assert pkg.sequence_number == 1

    def test_opcode_byte(self):
        raw = bytes.fromhex(HEX_OP25_IDK)
        assert raw[2] == OPCODE_EXTERNAL_SENDER_PACKAGE  # 0x19 = 25

    def test_signature_key_is_65_bytes_p256(self):
        raw = bytes.fromhex(HEX_OP25_IDK)
        pkg = parse_external_sender_package(raw)
        assert len(pkg.signature_key) == 65
        assert pkg.signature_key[0] == 0x04  # uncompressed P256

    def test_credential_type_is_basic(self):
        raw = bytes.fromhex(HEX_OP25_IDK)
        pkg = parse_external_sender_package(raw)
        assert pkg.credential_type == 1  # basic credential per MLS

    def test_identity_bytes(self):
        raw = bytes.fromhex(HEX_OP25_IDK)
        pkg = parse_external_sender_package(raw)
        assert isinstance(pkg.identity, bytes)
        assert len(pkg.identity) >= 1


class TestParseRealOp25Base64FromUdp:
    """Parse real opcode 25 from udp.txt capture (base64-encoded)."""

    def test_decode_base64(self):
        raw = base64.b64decode(B64_OP25_UDP)
        assert len(raw) == 74

    def test_parse_opcode_25(self):
        raw = base64.b64decode(B64_OP25_UDP)
        pkg = parse_external_sender_package(raw)
        assert pkg.sequence_number == 1
        assert len(pkg.signature_key) == 65
        assert pkg.signature_key[0] == 0x04
        assert pkg.credential_type == 1


class TestParseRealOp26HexFromIdk:
    """Parse real opcode 26 (key package) from idk capture (hex-encoded)."""

    def test_decode_hex(self):
        raw = bytes.fromhex(HEX_OP26_IDK)
        assert len(raw) == 394

    def test_opcode_byte(self):
        raw = bytes.fromhex(HEX_OP26_IDK)
        assert raw[0] == OPCODE_KEY_PACKAGE  # 0x1a = 26

    def test_mls_wire_format(self):
        raw = bytes.fromhex(HEX_OP26_IDK)
        mls_data = raw[1:]
        # MLS wire format: first 2 bytes = version/type tag
        wire_tag = struct.unpack("!H", mls_data[:2])[0]
        assert wire_tag == 0x0001  # MLSMessage KeyPackage


class TestParseRealOp26Base64FromUdp:
    """Parse real opcode 26 from udp.txt capture (base64-encoded)."""

    def test_decode_base64(self):
        raw = base64.b64decode(B64_OP26_UDP)
        assert len(raw) == 394

    def test_opcode_byte(self):
        raw = base64.b64decode(B64_OP26_UDP)
        assert raw[0] == OPCODE_KEY_PACKAGE

    def test_mls_wire_format(self):
        raw = base64.b64decode(B64_OP26_UDP)
        wire_tag = struct.unpack("!H", raw[1:3])[0]
        assert wire_tag == 0x0001


class TestRealJsonOp0Identify:
    """Parse real op 0 (identify) from idk capture."""

    def test_parse_json(self):
        obj = orjson.loads(JSON_OP0_IDK)
        assert obj["op"] == 0
        d = obj["d"]
        assert d["user_id"] == "256062279974387723"
        assert d["max_dave_protocol_version"] == 1
        assert d["server_id"] == "1043272195868217364"
        assert d["video"] is True

    def test_streams(self):
        obj = orjson.loads(JSON_OP0_IDK)
        streams = obj["d"]["streams"]
        assert len(streams) == 2
        qualities = {s["quality"] for s in streams}
        assert qualities == {50, 100}


class TestRealJsonOp4SessionDescription:
    """Parse real op 4 (select_protocol_ack) from idk capture."""

    def test_parse_json(self):
        obj = orjson.loads(JSON_OP4_IDK)
        assert obj["op"] == 4

    def test_dave_protocol_version(self):
        dave_ver = parse_select_protocol_ack(JSON_OP4_IDK.encode())
        assert dave_ver == 1

    def test_secret_key_is_32_bytes(self):
        obj = orjson.loads(JSON_OP4_IDK)
        key = obj["d"]["secret_key"]
        assert len(key) == 32
        assert all(0 <= b <= 255 for b in key)
        key_bytes = bytes(key)
        assert len(key_bytes) == 32

    def test_mode_is_aead_aes256_gcm(self):
        obj = orjson.loads(JSON_OP4_IDK)
        assert obj["d"]["mode"] == "aead_aes256_gcm_rtpsize"

    def test_codecs(self):
        obj = orjson.loads(JSON_OP4_IDK)
        assert obj["d"]["audio_codec"] == "opus"
        assert obj["d"]["video_codec"] == "H265"

    def test_secret_key_bytes_match_capture(self):
        obj = orjson.loads(JSON_OP4_IDK)
        expected = [
            254,
            118,
            6,
            145,
            6,
            5,
            71,
            9,
            200,
            63,
            91,
            105,
            46,
            188,
            124,
            39,
            34,
            0,
            41,
            49,
            173,
            135,
            77,
            7,
            104,
            74,
            50,
            97,
            125,
            113,
            180,
            145,
        ]
        assert obj["d"]["secret_key"] == expected


class TestRealJsonOp2Ready:
    """Parse real op 2 (ready) from idk capture."""

    def test_ssrc_and_port(self):
        obj = orjson.loads(JSON_OP2_IDK)
        d = obj["d"]
        assert d["ssrc"] == 7276
        assert d["port"] == 19311
        assert d["ip"] == "104.29.151.192"

    def test_modes(self):
        obj = orjson.loads(JSON_OP2_IDK)
        modes = obj["d"]["modes"]
        assert "aead_aes256_gcm_rtpsize" in modes

    def test_video_streams(self):
        obj = orjson.loads(JSON_OP2_IDK)
        streams = obj["d"]["streams"]
        assert len(streams) == 2
        for s in streams:
            assert s["type"] == "video"
            assert "ssrc" in s
            assert "rtx_ssrc" in s


class TestHexVsBase64SameStructure:
    """Verify that hex (idk) and base64 (udp.txt) op25 parse to same structure."""

    def test_same_opcode_and_credential_type(self):
        pkg_hex = parse_external_sender_package(bytes.fromhex(HEX_OP25_IDK))
        pkg_b64 = parse_external_sender_package(base64.b64decode(B64_OP25_UDP))

        assert pkg_hex.sequence_number == pkg_b64.sequence_number == 1
        assert pkg_hex.credential_type == pkg_b64.credential_type == 1
        assert len(pkg_hex.signature_key) == len(pkg_b64.signature_key) == 65

    def test_different_sessions_different_keys(self):
        pkg_hex = parse_external_sender_package(bytes.fromhex(HEX_OP25_IDK))
        pkg_b64 = parse_external_sender_package(base64.b64decode(B64_OP25_UDP))
        # Different sessions -> different external sender signature keys
        assert pkg_hex.signature_key != pkg_b64.signature_key
