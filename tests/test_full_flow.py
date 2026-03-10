"""
Full flow test from full.txt: I join, someone else joins, that person leaves, I leave.

Replays the captured voice gateway messages (JSON + hex-encoded binary) against
existing parsers and optionally DaveSession. Binary messages are decoded from hex.

DAVE opcode coverage (all opcodes 0, 4, 11, 13, 21–24, 25–31):

- In full.txt (this capture):
  - JSON: 0 (Identify), 4 (Select Protocol Ack), 11 (Clients Connect), 13 (Client Disconnect),
    21 (Prepare Transition), 24 (Prepare Epoch). Also gateway ops 2, 8, 16, 1, 15, 18, 20, 14, 3, 6, 12, 5.
  - Binary: 25 (External Sender), 26 (Key Package), 27 (Proposals), 28 (Commit/Welcome), 29 (Announce Commit).

- Not in full.txt (and why):
  - 22 (Execute Transition): server may omit when transition_id is 0; we only see 21 here.
  - 23 (Ready For Transition): client sends; not in a server capture.
  - 30 (Welcome): you do not receive this when you are the committer. The server sends Welcome
    to the newly added member(s); in this flow you joined first and sent the commit, so the
    other user gets the Welcome, not you. If you join after someone else, you would receive 30.
  - 31 (Invalid Commit/Welcome): client sends after InvalidCommitError; not from server.

All DAVE binary opcodes (25–30) are handled in _parse_binary_message so a capture that
includes op 30 (e.g. "someone else joins, then I join") will parse correctly.
"""

from __future__ import annotations

import struct
from pathlib import Path

import orjson
import pytest

from sorrydave.mls.opcodes import (
    OPCODE_ANNOUNCE_COMMIT,
    OPCODE_COMMIT_WELCOME,
    OPCODE_EXTERNAL_SENDER_PACKAGE,
    OPCODE_KEY_PACKAGE,
    OPCODE_PROPOSALS,
    OPCODE_WELCOME,
    parse_announce_commit,
    parse_client_disconnect,
    parse_clients_connect,
    parse_commit_welcome,
    parse_external_sender_package,
    parse_prepare_epoch,
    parse_prepare_transition,
    parse_proposals,
    parse_select_protocol_ack,
    parse_welcome_message,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_FULL_TXT_PATH = _REPO_ROOT / "full.txt"


def _load_full_txt_lines() -> list[str]:
    """Load non-empty lines from full.txt. Raises if file missing."""
    text = _FULL_TXT_PATH.read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _is_json_line(line: str) -> bool:
    return line.startswith("{")


def _parse_binary_line(line: str) -> bytes:
    return bytes.fromhex(line.replace(" ", ""))


def _parse_binary_message(raw: bytes) -> None:
    """
    Route hex-decoded binary to the correct parser. Asserts no parse error.
    Op 26, 28: 1-byte opcode then body. Op 25, 27, 29: 2-byte seq + 1-byte opcode + body.
    """
    if len(raw) < 1:
        raise ValueError("Binary message too short")
    if raw[0] == 0x1A:  # OPCODE_KEY_PACKAGE (26)
        assert raw[0] == OPCODE_KEY_PACKAGE
        if len(raw) >= 3:
            wire_tag = struct.unpack("!H", raw[1:3])[0]
            assert wire_tag == 0x0001  # MLSMessage KeyPackage
        return
    if raw[0] == 0x1C:  # OPCODE_COMMIT_WELCOME (28)
        parse_commit_welcome(raw)
        return
    if len(raw) >= 3:
        _seq = struct.unpack("!H", raw[:2])[0]
        opcode = raw[2]
        if opcode == OPCODE_EXTERNAL_SENDER_PACKAGE:  # 25
            parse_external_sender_package(raw)
            return
        if opcode == OPCODE_PROPOSALS:  # 27
            parse_proposals(raw)
            return
        if opcode == OPCODE_ANNOUNCE_COMMIT:  # 29
            parse_announce_commit(raw)
            return
        if opcode == OPCODE_WELCOME:  # 30 — not in full.txt; you get this when you were added (join after others)
            parse_welcome_message(raw)
            return
    raise ValueError(f"Unknown or unsupported binary opcode layout: first bytes {raw[:4].hex()!r}")


@pytest.mark.skipif(not _FULL_TXT_PATH.exists(), reason="full.txt not found")
class TestFullFlowParser:
    """Every message in full.txt parses without error (JSON or hex binary)."""

    def test_all_lines_parse(self):
        lines = _load_full_txt_lines()
        for i, line in enumerate(lines):
            if _is_json_line(line):
                obj = orjson.loads(line)
                assert isinstance(obj, dict)
                if "op" in obj:
                    assert isinstance(obj["op"], int)
            else:
                raw = _parse_binary_line(line)
                _parse_binary_message(raw)

    def test_json_op0_has_user_id(self):
        lines = _load_full_txt_lines()
        op0_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 0)
        obj = orjson.loads(op0_line)
        assert "user_id" in obj["d"]
        assert obj["d"]["user_id"] == "256062279974387723"

    def test_json_op4_has_dave_protocol_version(self):
        lines = _load_full_txt_lines()
        op4_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 4)
        obj = orjson.loads(op4_line)
        assert obj["d"]["dave_protocol_version"] == 1
        parse_select_protocol_ack(op4_line.encode())  # no raise

    def test_json_op11_has_user_ids(self):
        lines = _load_full_txt_lines()
        op11_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 11)
        user_ids = parse_clients_connect(op11_line.encode())
        assert user_ids == ["1136799305555005490"]

    def test_json_op13_client_disconnect(self):
        lines = _load_full_txt_lines()
        op13_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 13)
        user_id = parse_client_disconnect(op13_line.encode())
        assert user_id == "1136799305555005490"

    def test_binary_op25_external_sender_parses(self):
        lines = _load_full_txt_lines()
        bin_lines = [l for l in lines if not _is_json_line(l)]
        # First binary is op 26; second is op 25 (000119...)
        op25_line = next(l for l in bin_lines if l.startswith("0001") and len(l) < 200)
        raw = _parse_binary_line(op25_line)
        pkg = parse_external_sender_package(raw)
        assert pkg.sequence_number == 1
        assert len(pkg.signature_key) == 65

    def test_binary_op26_key_package_format(self):
        lines = _load_full_txt_lines()
        op26_lines = [l for l in lines if not _is_json_line(l) and l.startswith("1a")]
        assert len(op26_lines) >= 2  # first and final key packages
        for line in op26_lines:
            raw = _parse_binary_line(line)
            assert raw[0] == OPCODE_KEY_PACKAGE
            assert len(raw) > 1

    def test_binary_op27_proposals_parse(self):
        lines = _load_full_txt_lines()
        # op 27: 00061b00...
        op27_line = next(l for l in lines if not _is_json_line(l) and "1b00" in l[:20])
        raw = _parse_binary_line(op27_line)
        msg = parse_proposals(raw)
        assert msg.sequence_number == 6
        assert msg.operation_type == 0

    def test_binary_op28_commit_welcome_parses(self):
        lines = _load_full_txt_lines()
        op28_line = next(l for l in lines if not _is_json_line(l) and l.startswith("1c"))
        raw = _parse_binary_line(op28_line)
        commit_bytes, welcome_bytes = parse_commit_welcome(raw)
        assert isinstance(commit_bytes, bytes)
        assert welcome_bytes is None or isinstance(welcome_bytes, bytes)

    def test_binary_op29_announce_commit_parses(self):
        lines = _load_full_txt_lines()
        # op 29: 00071d00...
        op29_line = next(l for l in lines if not _is_json_line(l) and "1d00" in l[:20])
        raw = _parse_binary_line(op29_line)
        transition_id, commit_message = parse_announce_commit(raw)
        assert isinstance(transition_id, int)
        assert len(commit_message) > 0


@pytest.mark.skipif(not _FULL_TXT_PATH.exists(), reason="full.txt not found")
class TestFullFlowSessionReplay:
    """
    Drive DaveSession through the flow up to handle_proposals; parse op 28/29.
    Does not apply handle_commit with captured op 29 (server commit may differ from ours).
    """

    def test_session_through_proposals_and_parse_28_29(self):
        from sorrydave.session import DaveSession

        lines = _load_full_txt_lines()
        op0 = next(orjson.loads(l) for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 0)
        local_user_id = int(op0["d"]["user_id"])

        op25_line = next(l for l in lines if not _is_json_line(l) and l.startswith("0001") and len(l) < 200)
        op27_line = next(l for l in lines if not _is_json_line(l) and "1b00" in l[:20])
        op11_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 11)

        session = DaveSession(local_user_id=local_user_id)
        out = session.prepare_epoch(1)
        assert out is not None
        assert out[0] == OPCODE_KEY_PACKAGE

        raw_25 = _parse_binary_line(op25_line)
        session.handle_external_sender_package(raw_25)

        user_ids = parse_clients_connect(op11_line.encode())
        session.add_expected_members(user_ids)

        raw_27 = _parse_binary_line(op27_line)
        commit_welcome_payload = session.handle_proposals(raw_27)
        assert commit_welcome_payload is not None
        assert len(commit_welcome_payload) > 0
        assert commit_welcome_payload[0] == OPCODE_COMMIT_WELCOME

        op28_line = next(l for l in lines if not _is_json_line(l) and l.startswith("1c"))
        raw_28 = _parse_binary_line(op28_line)
        commit_bytes, welcome_bytes = parse_commit_welcome(raw_28)
        assert isinstance(commit_bytes, bytes)

        op29_line = next(l for l in lines if not _is_json_line(l) and "1d00" in l[:20])
        raw_29 = _parse_binary_line(op29_line)
        transition_id, announce_commit_bytes = parse_announce_commit(raw_29)
        assert transition_id == 0
        assert len(announce_commit_bytes) > 0

    def test_session_after_other_leaves_prepare_epoch_and_transition(self):
        from sorrydave.session import DaveSession

        lines = _load_full_txt_lines()
        op0 = next(orjson.loads(l) for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 0)
        local_user_id = int(op0["d"]["user_id"])
        op11_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 11)
        op13_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 13)
        op24_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 24)
        op21_line = next(l for l in lines if _is_json_line(l) and orjson.loads(l).get("op") == 21)
        op25_line = next(l for l in lines if not _is_json_line(l) and l.startswith("0001") and len(l) < 200)
        op27_line = next(l for l in lines if not _is_json_line(l) and "1b00" in l[:20])

        session = DaveSession(local_user_id=local_user_id)
        session.prepare_epoch(1)
        session.handle_external_sender_package(_parse_binary_line(op25_line))
        session.add_expected_members(parse_clients_connect(op11_line.encode()))
        session.handle_proposals(_parse_binary_line(op27_line))

        user_id_left = parse_client_disconnect(op13_line.encode())
        session.remove_expected_member(user_id_left)

        protocol_version, epoch = parse_prepare_epoch(op24_line.encode())
        assert protocol_version == 1
        assert epoch == 1
        session.prepare_epoch(epoch)

        protocol_version_21, transition_id = parse_prepare_transition(op21_line.encode())
        assert transition_id == 0
        session.execute_transition(transition_id)
        # After prepare_epoch(1) group was reset; no encryptor until new group is established
