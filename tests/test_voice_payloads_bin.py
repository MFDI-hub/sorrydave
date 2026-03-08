"""
Tests that run DAVE opcode parsing against real .bin payloads in voice_payloads/.

DAVE binary opcodes (25, 26, 27, 29, 30) are stored as .bin files; normal gateway
payloads are JSON. These tests load each .bin file, infer opcode from the filename
(e.g. recv_000010_op25.bin -> 25), and run the corresponding parser to ensure
the code handles real gateway payloads.

Skips if voice_payloads/ is missing or contains no .bin files.
"""

from pathlib import Path

import pytest
from sorrydave.mls.opcodes import (
    OPCODE_ANNOUNCE_COMMIT,
    OPCODE_COMMIT_WELCOME,
    OPCODE_EXTERNAL_SENDER_PACKAGE,
    OPCODE_KEY_PACKAGE,
    OPCODE_PROPOSALS,
    OPCODE_WELCOME,
    parse_announce_commit,
    parse_commit_welcome,
    parse_external_sender_package,
    parse_proposals,
    parse_welcome_message,
)

# Repo root: parent of tests/
_REPO_ROOT = Path(__file__).resolve().parent.parent
_VOICE_PAYLOADS_DIR = _REPO_ROOT / "voice_payloads"


def _collect_bin_payloads():
    """Yield (path, opcode) for each .bin file under voice_payloads."""
    if not _VOICE_PAYLOADS_DIR.is_dir():
        return
    for path in _VOICE_PAYLOADS_DIR.rglob("*.bin"):
        name = path.name
        # e.g. recv_000010_op25.bin, sent_000006_op26.bin
        if "_op" in name and name.endswith(".bin"):
            try:
                rest = name.split("_op")[-1]
                op_str = rest.replace(".bin", "").strip()
                opcode = int(op_str)
                if 22 <= opcode <= 31:
                    yield path, opcode
            except ValueError:
                continue


_BIN_PAYLOADS = list(_collect_bin_payloads())


def _opcode_supported_for_parse(opcode: int) -> bool:
    """Binary DAVE opcodes we can parse from .bin (25, 26, 27, 28, 29, 30)."""
    return opcode in (
        OPCODE_EXTERNAL_SENDER_PACKAGE,  # 25
        OPCODE_KEY_PACKAGE,              # 26
        OPCODE_PROPOSALS,                # 27
        OPCODE_COMMIT_WELCOME,           # 28
        OPCODE_ANNOUNCE_COMMIT,          # 29
        OPCODE_WELCOME,                  # 30
    )


@pytest.mark.skipif(
    len(_BIN_PAYLOADS) == 0,
    reason="No .bin files in voice_payloads/ (optional DAVE payload fixtures)",
)
@pytest.mark.parametrize(
    "path,opcode",
    _BIN_PAYLOADS,
    ids=[p.name for p, _ in _BIN_PAYLOADS],
)
def test_voice_payload_bin_parses(path: Path, opcode: int):
    """
    Load each DAVE .bin payload and run the matching parser.
    Ensures opcode parsing works against real gateway payloads.
    """
    data = path.read_bytes()
    assert len(data) > 0, f"Empty file: {path}"

    if not _opcode_supported_for_parse(opcode):
        pytest.skip(f"Opcode {opcode} has no binary parser in this test (JSON or other).")

    if opcode == OPCODE_EXTERNAL_SENDER_PACKAGE:
        pkg = parse_external_sender_package(data)
        assert pkg.sequence_number >= 0
        assert isinstance(pkg.signature_key, bytes)
        assert isinstance(pkg.identity, bytes)
        return
    if opcode == OPCODE_KEY_PACKAGE:
        # Sent op26: opcode (1) || key_package (MLSMessage)
        assert data[0] == OPCODE_KEY_PACKAGE, f"Expected opcode 26, got {data[0]}"
        assert len(data) > 1, "Key package payload empty"
        return
    if opcode == OPCODE_PROPOSALS:
        msg = parse_proposals(data)
        assert msg.sequence_number >= 0
        assert msg.operation_type in (0, 1)
        if msg.operation_type == 0:
            assert msg.proposal_messages is not None
        else:
            assert msg.proposal_refs is not None
        return
    if opcode == OPCODE_COMMIT_WELCOME:
        commit_bytes, welcome_bytes = parse_commit_welcome(data)
        assert isinstance(commit_bytes, bytes)
        assert len(commit_bytes) > 0
        if welcome_bytes is not None:
            assert isinstance(welcome_bytes, bytes)
        return
    if opcode == OPCODE_ANNOUNCE_COMMIT:
        transition_id, commit_bytes = parse_announce_commit(data)
        assert 0 <= transition_id <= 0xFFFF
        assert isinstance(commit_bytes, bytes)
        return
    if opcode == OPCODE_WELCOME:
        transition_id, welcome_bytes = parse_welcome_message(data)
        assert 0 <= transition_id <= 0xFFFF
        assert isinstance(welcome_bytes, bytes)
        return


@pytest.mark.skipif(
    len(_BIN_PAYLOADS) == 0,
    reason="No .bin files in voice_payloads/",
)
def test_voice_payloads_bin_at_least_one_dave_opcode():
    """Sanity: at least one .bin file is a DAVE binary opcode (25, 26, 27, 28, 29, 30)."""
    dave_opcodes = {25, 26, 27, 28, 29, 30}
    found = {op for _, op in _BIN_PAYLOADS if op in dave_opcodes}
    assert len(found) > 0, (
        "No DAVE binary opcodes (25–30) found in .bin filenames. "
        "Expected names like recv_000010_op25.bin or sent_000006_op26.bin."
    )
