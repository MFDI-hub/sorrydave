"""
DAVE protocol exceptions.

All protocol-specific errors inherit from DaveProtocolError for easy catching.
"""


class DaveProtocolError(Exception):
    """
    Base exception for all DAVE protocol errors.

    Catch this to handle any protocol-level failure.
    """

    pass


class DecryptionError(DaveProtocolError):
    """
    Raised on decryption failure: GCM tag mismatch, nonce reuse, or key mismatch.

    Fail-closed: drop the frame and do not process.
    """

    pass


class InvalidCommitError(DaveProtocolError):
    """
    Raised when a commit or welcome message cannot be processed.

    Triggers state reset; application should send opcode 31 and submit new KeyPackage (26).
    """

    pass
