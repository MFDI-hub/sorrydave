"""
Codec-aware unencrypted range parsers for DAVE frame transform.
MVP: OPUS (full encrypt), VP9 (full encrypt), VP8 (P-bit header).
"""

from pydave.types import UnencryptedRange

# VP8 payload header per RFC 7741: P is inverse key frame (bit 0 of first byte)
VP8_HEADER_KEYFRAME_LEN = 10
VP8_HEADER_DELTA_LEN = 1


def get_unencrypted_ranges(frame: bytes, codec: str) -> list[UnencryptedRange]:
    """
    Return unencrypted byte ranges for the given codec and frame.
    - OPUS, VP9: full frame encrypted -> [].
    - VP8: 1 or 10 bytes unencrypted based on P bit (inverse key frame).
    - Unknown codec or parse error: treat as full encrypt (return [] for safe behavior;
      transform layer will encrypt entire frame when ranges are empty).
    """
    codec_upper = codec.strip().upper() if codec else ""
    if codec_upper == "OPUS" or codec_upper == "VP9":
        return []
    if codec_upper == "VP8":
        return _vp8_unencrypted_ranges(frame)
    # Unknown or unsupported: encrypt entire frame
    return []


def _vp8_unencrypted_ranges(frame: bytes) -> list[UnencryptedRange]:
    """
    VP8: first byte has P (inverse key frame) in least significant bit.
    P=0 -> key frame -> 10 bytes unencrypted.
    P=1 -> delta frame -> 1 byte unencrypted.
    """
    if len(frame) < 1:
        return []
    # RFC 7741 section 4.3: P is bit 0 (LSB)
    p_bit = frame[0] & 1
    if p_bit == 0:
        length = min(VP8_HEADER_KEYFRAME_LEN, len(frame))
    else:
        length = VP8_HEADER_DELTA_LEN
    return [UnencryptedRange(offset=0, length=length)]
