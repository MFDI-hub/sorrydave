"""
DAVE protocol exceptions.

All protocol-specific errors inherit from DaveProtocolError for easy catching.
"""


class DaveProtocolError(Exception):
    """
    Base exception for all DAVE protocol errors.

    When raised: Any protocol-level failure from the library. Catch this to handle
    all DAVE errors (including DecryptionError and InvalidCommitError) in one block.
    """

    pass


class DecryptionError(DaveProtocolError):
    """
    Raised on decryption failure: GCM tag mismatch, nonce reuse, or key mismatch.

    When raised: Typically from FrameDecryptor.decrypt(). Fail-closed: drop the
    frame and do not process; do not retry with the same frame.
    """

    pass


class InvalidCommitError(DaveProtocolError):
    """
    Raised when a commit or welcome message cannot be processed.

    When raised: From session.handle_commit() (or group_state.apply_commit).
    Recovery: Send opcode 31 (build_invalid_commit_welcome(transition_id)), then
    session.prepare_epoch(1) and send the returned key package as opcode 26.
    """

    pass
