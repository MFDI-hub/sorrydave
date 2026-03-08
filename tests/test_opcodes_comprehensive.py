"""Comprehensive opcode tests: all parsers, builders, edge cases, and error conditions."""

import json

import pytest

from sorrydave.mls.opcodes import (
    OPCODE_ANNOUNCE_COMMIT,
    OPCODE_CLIENT_DISCONNECT,
    OPCODE_CLIENTS_CONNECT,
    OPCODE_COMMIT_WELCOME,
    OPCODE_EXECUTE_TRANSITION,
    OPCODE_EXTERNAL_SENDER_PACKAGE,
    OPCODE_IDENTIFY,
    OPCODE_INVALID_COMMIT_WELCOME,
    OPCODE_KEY_PACKAGE,
    OPCODE_PREPARE_EPOCH,
    OPCODE_PREPARE_TRANSITION,
    OPCODE_PROPOSALS,
    OPCODE_READY_FOR_TRANSITION,
    OPCODE_SELECT_PROTOCOL_ACK,
    OPCODE_WELCOME,
    ExternalSenderPackage,
    build_commit_welcome,
    build_identify,
    build_invalid_commit_welcome,
    build_key_package_message,
    build_ready_for_transition,
    parse_announce_commit,
    parse_client_disconnect,
    parse_clients_connect,
    parse_commit_welcome,
    parse_execute_transition,
    parse_external_sender_package,
    parse_prepare_epoch,
    parse_prepare_transition,
    parse_proposals,
    parse_select_protocol_ack,
    parse_welcome_message,
    split_proposal_messages_vector,
    _read_varint,
    _read_opaque_varint,
    _write_opaque_varint,
)
import struct


# ---------------------------------------------------------------------------
# Varint helpers
# ---------------------------------------------------------------------------

class TestMlsVarint:
    def test_1_byte(self):
        val, off = _read_varint(b"\x05", 0)
        assert val == 5
        assert off == 1

    def test_2_byte(self):
        data = bytes([0x40 | 0x01, 0x00])
        val, off = _read_varint(data, 0)
        assert val == 256
        assert off == 2

    def test_4_byte(self):
        data = bytes([0x80, 0x01, 0x00, 0x00])
        val, off = _read_varint(data, 0)
        assert val == (1 << 16)
        assert off == 4

    def test_overflow_raises(self):
        with pytest.raises(ValueError, match="overflow"):
            _read_varint(bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0)

    def test_truncated_raises(self):
        with pytest.raises(ValueError, match="truncated"):
            _read_varint(b"", 0)
        with pytest.raises(ValueError, match="truncated"):
            _read_varint(bytes([0x40]), 0)

    def test_offset(self):
        data = b"\xFF\x05\xFF"
        val, off = _read_varint(data, 1)
        assert val == 5
        assert off == 2


class TestOpaqueVarint:
    def test_roundtrip(self):
        payload = b"hello"
        encoded = _write_opaque_varint(payload)
        decoded, off = _read_opaque_varint(encoded, 0)
        assert decoded == payload
        assert off == len(encoded)

    def test_empty_payload(self):
        encoded = _write_opaque_varint(b"")
        decoded, off = _read_opaque_varint(encoded, 0)
        assert decoded == b""

    def test_truncated_raises(self):
        with pytest.raises(ValueError, match="truncated"):
            _read_opaque_varint(bytes([0x05]), 0)


# ---------------------------------------------------------------------------
# ExternalSenderPackage (opcode 25)
# ---------------------------------------------------------------------------

class TestParseExternalSenderPackage:
    def _build_pkg(self, seq=0, opcode=25, sig_key=b"\xAA\xBB", cred_type=1, identity=b"\x01\x02"):
        out = struct.pack("!H", seq)
        out += bytes([opcode])
        out += bytes([len(sig_key)]) + sig_key
        out += struct.pack("!H", cred_type)
        out += bytes([len(identity)]) + identity
        return out

    def test_valid(self):
        data = self._build_pkg()
        pkg = parse_external_sender_package(data)
        assert pkg.sequence_number == 0
        assert pkg.signature_key == b"\xAA\xBB"
        assert pkg.credential_type == 1
        assert pkg.identity == b"\x01\x02"

    def test_wrong_opcode(self):
        data = self._build_pkg(opcode=26)
        with pytest.raises(ValueError, match="opcode 25"):
            parse_external_sender_package(data)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_external_sender_package(b"\x00\x00")

    def test_empty_sig_key(self):
        data = self._build_pkg(sig_key=b"")
        pkg = parse_external_sender_package(data)
        assert pkg.signature_key == b""

    def test_large_seq(self):
        data = self._build_pkg(seq=0xFFFF)
        pkg = parse_external_sender_package(data)
        assert pkg.sequence_number == 0xFFFF


# ---------------------------------------------------------------------------
# KeyPackage (opcode 26)
# ---------------------------------------------------------------------------

class TestBuildKeyPackageMessage:
    def test_basic(self):
        kp = b"\x01\x02\x03"
        result = build_key_package_message(kp)
        assert result[0] == OPCODE_KEY_PACKAGE
        assert result[1:] == kp

    def test_empty_kp(self):
        result = build_key_package_message(b"")
        assert result == bytes([OPCODE_KEY_PACKAGE])


# ---------------------------------------------------------------------------
# Proposals (opcode 27)
# ---------------------------------------------------------------------------

class TestParseProposals:
    def _build_proposals(self, seq=0, op_type=0, vector_payload=b"\xAA"):
        out = struct.pack("!H", seq)
        out += bytes([OPCODE_PROPOSALS, op_type])
        out += bytes([len(vector_payload)]) + vector_payload
        return out

    def test_append(self):
        data = self._build_proposals(op_type=0, vector_payload=b"\x01\x02")
        msg = parse_proposals(data)
        assert msg.operation_type == 0
        assert msg.proposal_messages is not None
        assert len(msg.proposal_messages) == 1

    def test_revoke(self):
        ref = b"\xAA\xBB\xCC"
        inner = bytes([len(ref)]) + ref
        data = self._build_proposals(op_type=1, vector_payload=inner)
        msg = parse_proposals(data)
        assert msg.operation_type == 1
        assert msg.proposal_refs is not None
        assert len(msg.proposal_refs) == 1
        assert msg.proposal_refs[0] == ref

    def test_wrong_opcode(self):
        data = struct.pack("!H", 0) + bytes([26, 0]) + bytes([0x01, 0xAA])
        with pytest.raises(ValueError, match="opcode 27"):
            parse_proposals(data)

    def test_unknown_op_type(self):
        data = self._build_proposals(op_type=5)
        with pytest.raises(ValueError, match="operation type"):
            parse_proposals(data)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_proposals(b"\x00\x00\x1B")


class TestSplitProposalMessagesVector:
    def test_single_message(self):
        msg = b"\xAA\xBB\xCC"
        vector = bytes([len(msg)]) + msg
        result = split_proposal_messages_vector(vector)
        assert result == [msg]

    def test_multiple_messages(self):
        msg1 = b"\x01\x02"
        msg2 = b"\x03\x04\x05"
        vector = bytes([len(msg1)]) + msg1 + bytes([len(msg2)]) + msg2
        result = split_proposal_messages_vector(vector)
        assert result == [msg1, msg2]

    def test_empty(self):
        assert split_proposal_messages_vector(b"") == []

    def test_truncated_graceful(self):
        result = split_proposal_messages_vector(bytes([0x05, 0xAA]))
        assert result == []


# ---------------------------------------------------------------------------
# CommitWelcome (opcode 28)
# ---------------------------------------------------------------------------

class TestBuildParseCommitWelcome:
    def test_commit_only(self):
        commit = b"\x01\x02\x03"
        built = build_commit_welcome(commit, None)
        parsed_commit, parsed_welcome = parse_commit_welcome(built)
        assert parsed_commit == commit
        assert parsed_welcome is None

    def test_commit_with_welcome(self):
        commit = b"\x01\x02\x03"
        welcome = b"\x04\x05\x06"
        built = build_commit_welcome(commit, welcome)
        parsed_commit, parsed_welcome = parse_commit_welcome(built)
        assert parsed_commit == commit
        assert parsed_welcome == welcome

    def test_wrong_opcode(self):
        data = bytes([29]) + _write_opaque_varint(b"\x01")
        with pytest.raises(ValueError, match="opcode 28"):
            parse_commit_welcome(data)

    def test_empty_commit(self):
        built = build_commit_welcome(b"", None)
        parsed_commit, parsed_welcome = parse_commit_welcome(built)
        assert parsed_commit == b""
        assert parsed_welcome is None

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_commit_welcome(b"")


# ---------------------------------------------------------------------------
# AnnounceCommit (opcode 29)
# ---------------------------------------------------------------------------

class TestParseAnnounceCommit:
    def test_valid(self):
        data = struct.pack("!H", 0) + bytes([OPCODE_ANNOUNCE_COMMIT]) + struct.pack("!H", 42)
        data += b"\xAA\xBB"
        tid, commit = parse_announce_commit(data)
        assert tid == 42
        assert commit == b"\xAA\xBB"

    def test_wrong_opcode(self):
        data = struct.pack("!H", 0) + bytes([28]) + struct.pack("!H", 0)
        with pytest.raises(ValueError, match="opcode 29"):
            parse_announce_commit(data)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_announce_commit(b"\x00\x00\x1D")


# ---------------------------------------------------------------------------
# WelcomeMessage (opcode 30)
# ---------------------------------------------------------------------------

class TestParseWelcomeMessage:
    def test_valid(self):
        data = struct.pack("!H", 0) + bytes([OPCODE_WELCOME]) + struct.pack("!H", 99)
        data += b"\xCC\xDD"
        tid, welcome = parse_welcome_message(data)
        assert tid == 99
        assert welcome == b"\xCC\xDD"

    def test_wrong_opcode(self):
        data = struct.pack("!H", 0) + bytes([29]) + struct.pack("!H", 0)
        with pytest.raises(ValueError, match="opcode 30"):
            parse_welcome_message(data)

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_welcome_message(b"\x00\x00\x1E")


# ---------------------------------------------------------------------------
# ExecuteTransition (opcode 22)
# ---------------------------------------------------------------------------

class TestParseExecuteTransition:
    def test_valid(self):
        payload = json.dumps({"op": 22, "d": {"transition_id": 10}}).encode()
        assert parse_execute_transition(payload) == 10

    def test_missing_d(self):
        payload = json.dumps({"op": 22}).encode()
        with pytest.raises(ValueError, match="'d' object"):
            parse_execute_transition(payload)

    def test_missing_tid(self):
        payload = json.dumps({"op": 22, "d": {}}).encode()
        with pytest.raises(ValueError, match="transition_id"):
            parse_execute_transition(payload)

    def test_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid"):
            parse_execute_transition(b"not json")

    def test_tid_out_of_range(self):
        payload = json.dumps({"op": 22, "d": {"transition_id": 0x10000}}).encode()
        with pytest.raises(ValueError, match="uint16"):
            parse_execute_transition(payload)

    def test_tid_zero(self):
        payload = json.dumps({"op": 22, "d": {"transition_id": 0}}).encode()
        assert parse_execute_transition(payload) == 0

    def test_tid_max(self):
        payload = json.dumps({"op": 22, "d": {"transition_id": 0xFFFF}}).encode()
        assert parse_execute_transition(payload) == 0xFFFF

    def test_d_is_array(self):
        payload = json.dumps({"op": 22, "d": [1, 2]}).encode()
        with pytest.raises(ValueError, match="'d' object"):
            parse_execute_transition(payload)

    def test_payload_is_array(self):
        payload = json.dumps([1, 2]).encode()
        with pytest.raises(ValueError, match="JSON object"):
            parse_execute_transition(payload)

    def test_tid_string_coercion(self):
        payload = json.dumps({"op": 22, "d": {"transition_id": "10"}}).encode()
        assert parse_execute_transition(payload) == 10


# ---------------------------------------------------------------------------
# InvalidCommitWelcome (opcode 31)
# ---------------------------------------------------------------------------

class TestBuildInvalidCommitWelcome:
    def test_valid(self):
        result = build_invalid_commit_welcome(42)
        obj = json.loads(result)
        assert obj["op"] == OPCODE_INVALID_COMMIT_WELCOME
        assert obj["d"]["transition_id"] == 42

    def test_out_of_range(self):
        with pytest.raises(ValueError, match="uint16"):
            build_invalid_commit_welcome(0x10000)
        with pytest.raises(ValueError, match="uint16"):
            build_invalid_commit_welcome(-1)

    def test_zero(self):
        result = build_invalid_commit_welcome(0)
        obj = json.loads(result)
        assert obj["d"]["transition_id"] == 0


# ---------------------------------------------------------------------------
# Identify (opcode 0)
# ---------------------------------------------------------------------------

class TestBuildIdentify:
    def test_basic(self):
        result = build_identify(1)
        obj = json.loads(result)
        assert obj["op"] == OPCODE_IDENTIFY
        assert obj["d"]["max_dave_protocol_version"] == 1

    def test_extra_fields(self):
        result = build_identify(1, server_id="123", user_id="456")
        obj = json.loads(result)
        assert obj["d"]["server_id"] == "123"
        assert obj["d"]["user_id"] == "456"

    def test_custom_version(self):
        result = build_identify(2)
        obj = json.loads(result)
        assert obj["d"]["max_dave_protocol_version"] == 2


# ---------------------------------------------------------------------------
# SelectProtocolAck (opcode 4)
# ---------------------------------------------------------------------------

class TestParseSelectProtocolAck:
    def test_valid(self):
        payload = json.dumps({"op": 4, "d": {"dave_protocol_version": 1}}).encode()
        assert parse_select_protocol_ack(payload) == 1

    def test_missing_d(self):
        payload = json.dumps({"op": 4}).encode()
        with pytest.raises(ValueError, match="'d' object"):
            parse_select_protocol_ack(payload)

    def test_missing_version(self):
        payload = json.dumps({"op": 4, "d": {}}).encode()
        with pytest.raises(ValueError, match="dave_protocol_version"):
            parse_select_protocol_ack(payload)

    def test_string_coercion(self):
        payload = json.dumps({"op": 4, "d": {"dave_protocol_version": "1"}}).encode()
        assert parse_select_protocol_ack(payload) == 1

    def test_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid"):
            parse_select_protocol_ack(b"{bad")


# ---------------------------------------------------------------------------
# ClientsConnect (opcode 11)
# ---------------------------------------------------------------------------

class TestParseClientsConnect:
    def test_valid(self):
        payload = json.dumps({"op": 11, "d": {"user_ids": ["123", "456"]}}).encode()
        result = parse_clients_connect(payload)
        assert result == ["123", "456"]

    def test_empty_list(self):
        payload = json.dumps({"op": 11, "d": {"user_ids": []}}).encode()
        assert parse_clients_connect(payload) == []

    def test_not_strings(self):
        payload = json.dumps({"op": 11, "d": {"user_ids": [123]}}).encode()
        with pytest.raises(ValueError, match="strings"):
            parse_clients_connect(payload)

    def test_missing_user_ids(self):
        payload = json.dumps({"op": 11, "d": {}}).encode()
        with pytest.raises(ValueError, match="list"):
            parse_clients_connect(payload)


# ---------------------------------------------------------------------------
# ClientDisconnect (opcode 13)
# ---------------------------------------------------------------------------

class TestParseClientDisconnect:
    def test_valid(self):
        payload = json.dumps({"op": 13, "d": {"user_id": "789"}}).encode()
        assert parse_client_disconnect(payload) == "789"

    def test_not_string(self):
        payload = json.dumps({"op": 13, "d": {"user_id": 789}}).encode()
        with pytest.raises(ValueError, match="string"):
            parse_client_disconnect(payload)

    def test_missing(self):
        payload = json.dumps({"op": 13, "d": {}}).encode()
        with pytest.raises(ValueError, match="string"):
            parse_client_disconnect(payload)


# ---------------------------------------------------------------------------
# PrepareTransition (opcode 21)
# ---------------------------------------------------------------------------

class TestParsePrepareTransition:
    def test_valid(self):
        payload = json.dumps({"op": 21, "d": {"protocol_version": 1, "transition_id": 5}}).encode()
        pv, tid = parse_prepare_transition(payload)
        assert pv == 1
        assert tid == 5

    def test_transition_id_zero(self):
        payload = json.dumps({"op": 21, "d": {"protocol_version": 1, "transition_id": 0}}).encode()
        _, tid = parse_prepare_transition(payload)
        assert tid == 0

    def test_missing_fields(self):
        payload = json.dumps({"op": 21, "d": {}}).encode()
        with pytest.raises(ValueError, match="required"):
            parse_prepare_transition(payload)

    def test_tid_out_of_range(self):
        payload = json.dumps({"op": 21, "d": {"protocol_version": 1, "transition_id": 0x10000}}).encode()
        with pytest.raises(ValueError, match="uint16"):
            parse_prepare_transition(payload)

    def test_negative_tid(self):
        payload = json.dumps({"op": 21, "d": {"protocol_version": 1, "transition_id": -1}}).encode()
        with pytest.raises(ValueError, match="uint16"):
            parse_prepare_transition(payload)


# ---------------------------------------------------------------------------
# ReadyForTransition (opcode 23)
# ---------------------------------------------------------------------------

class TestBuildReadyForTransition:
    def test_valid(self):
        result = build_ready_for_transition(10)
        obj = json.loads(result)
        assert obj["op"] == OPCODE_READY_FOR_TRANSITION
        assert obj["d"]["transition_id"] == 10

    def test_out_of_range(self):
        with pytest.raises(ValueError, match="uint16"):
            build_ready_for_transition(0x10000)
        with pytest.raises(ValueError, match="uint16"):
            build_ready_for_transition(-1)

    def test_zero(self):
        result = build_ready_for_transition(0)
        obj = json.loads(result)
        assert obj["d"]["transition_id"] == 0


# ---------------------------------------------------------------------------
# PrepareEpoch (opcode 24)
# ---------------------------------------------------------------------------

class TestParsePrepareEpoch:
    def test_valid(self):
        payload = json.dumps({"op": 24, "d": {"protocol_version": 1, "epoch": 1}}).encode()
        pv, epoch = parse_prepare_epoch(payload)
        assert pv == 1
        assert epoch == 1

    def test_epoch_zero(self):
        payload = json.dumps({"op": 24, "d": {"protocol_version": 1, "epoch": 0}}).encode()
        _, epoch = parse_prepare_epoch(payload)
        assert epoch == 0

    def test_missing_fields(self):
        payload = json.dumps({"op": 24, "d": {}}).encode()
        with pytest.raises(ValueError, match="required"):
            parse_prepare_epoch(payload)


# ---------------------------------------------------------------------------
# Opcode constants
# ---------------------------------------------------------------------------

class TestOpcodeConstants:
    def test_all_unique(self):
        opcodes = [
            OPCODE_IDENTIFY, OPCODE_SELECT_PROTOCOL_ACK, OPCODE_CLIENTS_CONNECT,
            OPCODE_CLIENT_DISCONNECT, OPCODE_PREPARE_TRANSITION, OPCODE_EXECUTE_TRANSITION,
            OPCODE_READY_FOR_TRANSITION, OPCODE_PREPARE_EPOCH, OPCODE_EXTERNAL_SENDER_PACKAGE,
            OPCODE_KEY_PACKAGE, OPCODE_PROPOSALS, OPCODE_COMMIT_WELCOME, OPCODE_ANNOUNCE_COMMIT,
            OPCODE_WELCOME, OPCODE_INVALID_COMMIT_WELCOME,
        ]
        assert len(opcodes) == len(set(opcodes))

    def test_expected_values(self):
        assert OPCODE_IDENTIFY == 0
        assert OPCODE_SELECT_PROTOCOL_ACK == 4
        assert OPCODE_CLIENTS_CONNECT == 11
        assert OPCODE_CLIENT_DISCONNECT == 13
        assert OPCODE_PREPARE_TRANSITION == 21
        assert OPCODE_EXECUTE_TRANSITION == 22
        assert OPCODE_READY_FOR_TRANSITION == 23
        assert OPCODE_PREPARE_EPOCH == 24
        assert OPCODE_EXTERNAL_SENDER_PACKAGE == 25
        assert OPCODE_KEY_PACKAGE == 26
        assert OPCODE_PROPOSALS == 27
        assert OPCODE_COMMIT_WELCOME == 28
        assert OPCODE_ANNOUNCE_COMMIT == 29
        assert OPCODE_WELCOME == 30
        assert OPCODE_INVALID_COMMIT_WELCOME == 31
