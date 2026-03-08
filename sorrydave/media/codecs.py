"""
Codec-aware unencrypted range parsers for DAVE frame transform.
OPUS, VP9 (full encrypt); VP8 (P-bit header); H264, H265 (NAL); AV1 (OBU).
"""

from sorrydave.types import UnencryptedRange

# VP8 payload header per RFC 7741: P is inverse key frame (bit 0 of first byte)
VP8_HEADER_KEYFRAME_LEN = 10
VP8_HEADER_DELTA_LEN = 1

# H264: NAL unit type in low 5 bits of first byte; VCL = 1-5
H264_VCL_TYPES = frozenset(range(1, 6))
# H265: NAL unit type in (first_byte & 0x7E) >> 1; VCL = 0-31, non-VCL = 32-63
H265_NAL_HEADER_LEN = 2
# AV1: OBU types dropped by packetizer (protocol.md)
AV1_OBU_DROP_TYPES = frozenset({2, 8, 15})  # TEMPORAL_DELIMITER, TILE_LIST, PADDING


def get_unencrypted_ranges(frame: bytes, codec: str) -> list[UnencryptedRange]:
    """
    Return unencrypted byte ranges for the given codec and frame.

    OPUS, VP9: full frame encrypted -> []. VP8: 1 or 10 bytes by P bit. H264/H265:
    non-VCL NAL header unencrypted. AV1: OBU header/extension/size unencrypted.
    Unknown codec or parse error returns [] (full encrypt).

    Args:
        frame (bytes): Encoded media frame.
        codec (str): Codec name (e.g. "VP8", "H264", "AV1").

    Returns:
        list[UnencryptedRange]: Ranges to leave plaintext; empty means encrypt entire frame.
    """
    codec_upper = codec.strip().upper() if codec else ""
    if codec_upper == "OPUS" or codec_upper == "VP9":
        return []
    if codec_upper == "VP8":
        return _vp8_unencrypted_ranges(frame)
    if codec_upper in ("H264", "H.264"):
        return _h264_unencrypted_ranges(frame)
    if codec_upper in ("H265", "H265/HEVC", "HEVC"):
        return _h265_unencrypted_ranges(frame)
    if codec_upper == "AV1":
        return _av1_unencrypted_ranges(frame)
    # Unknown or unsupported: encrypt entire frame
    return []


def _vp8_unencrypted_ranges(frame: bytes) -> list[UnencryptedRange]:
    """
    VP8 unencrypted ranges: P bit (LSB of first byte) determines header length.

    Args:
        frame (bytes): VP8 payload.

    Returns:
        list[UnencryptedRange]: P=0 -> 10 bytes; P=1 -> 1 byte; empty if frame too short.
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


def _find_next_start_code(data: bytes, pos: int) -> int:
    """
    Find start index of next Annex B start code (3- or 4-byte).

    Args:
        data (bytes): Buffer to search.
        pos (int): Offset to start searching.

    Returns:
        int: Start index of next 0x000001 or 0x00000001, or len(data) if not found.
    """
    n = len(data)
    while pos < n - 2:
        if data[pos] == 0 and data[pos + 1] == 0:
            if data[pos + 2] == 1:
                return pos
            if pos + 3 < n and data[pos + 2] == 0 and data[pos + 3] == 1:
                return pos
        pos += 1
    return n


def _h264_unencrypted_ranges(frame: bytes) -> list[UnencryptedRange]:
    """
    H264 Annex B: non-VCL NAL units get 1-byte header unencrypted; VCL fully encrypted.

    Args:
        frame (bytes): H264 frame with start codes.

    Returns:
        list[UnencryptedRange]: One range per non-VCL NAL (offset=NAL start, length=1).
    """
    ranges: list[UnencryptedRange] = []
    pos = 0
    n = len(frame)
    while pos < n:
        start = _find_next_start_code(frame, pos)
        if start >= n:
            break
        # start code length
        if start + 3 <= n and frame[start : start + 3] == b"\x00\x00\x01":
            sc_len = 3
        else:
            sc_len = 4
        nal_start = start + sc_len
        if nal_start >= n:
            break
        nal_type = frame[nal_start] & 0x1F
        # Find end of this NAL (start of next start code)
        next_start = _find_next_start_code(frame, nal_start + 1)
        if nal_type not in H264_VCL_TYPES:
            # Non-VCL: leave 1 byte header unencrypted
            ranges.append(UnencryptedRange(offset=nal_start, length=1))
        pos = next_start
    return ranges


def _h265_unencrypted_ranges(frame: bytes) -> list[UnencryptedRange]:
    """
    H265/HEVC Annex B: non-VCL NAL (type 32+) get 2-byte header unencrypted; VCL encrypted.

    Args:
        frame (bytes): H265 frame with start codes.

    Returns:
        list[UnencryptedRange]: One range per non-VCL NAL (2-byte header).
    """
    ranges: list[UnencryptedRange] = []
    pos = 0
    n = len(frame)
    while pos < n:
        start = _find_next_start_code(frame, pos)
        if start >= n:
            break
        if start + 3 <= n and frame[start : start + 3] == b"\x00\x00\x01":
            sc_len = 3
        else:
            sc_len = 4
        nal_start = start + sc_len
        if nal_start + H265_NAL_HEADER_LEN > n:
            break
        # Type in first byte: (byte & 0x7E) >> 1
        nal_type = (frame[nal_start] & 0x7E) >> 1
        next_start = _find_next_start_code(frame, nal_start + 1)
        if nal_type >= 32:
            # Non-VCL
            ranges.append(
                UnencryptedRange(
                    offset=nal_start, length=min(H265_NAL_HEADER_LEN, next_start - nal_start)
                )
            )
        pos = next_start
    return ranges


def _leb128_decode(data: bytes, offset: int) -> tuple[int, int]:
    """
    Decode one LEB128 value from data at offset.

    Args:
        data (bytes): Buffer containing LEB128.
        offset (int): Start index.

    Returns:
        tuple[int, int]: (value, new_offset).
    """
    val = 0
    shift = 0
    pos = offset
    while pos < len(data):
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if b < 0x80:
            return val, pos
        shift += 7
        if shift >= 56:
            break
    return val, pos


def _leb128_encode_minimal(value: int) -> bytes:
    """
    Encode nonnegative integer as minimal LEB128 (no padding).

    Args:
        value (int): Nonnegative integer.

    Returns:
        bytes: Minimal LEB128 encoding.
    """
    if value < 0:
        raise ValueError("LEB128 requires nonnegative integer")
    buf = []
    while value >= 0x80:
        buf.append(0x80 | (value & 0x7F))
        value >>= 7
    buf.append(value & 0x7F)
    return bytes(buf)


def _av1_unencrypted_ranges(frame: bytes) -> list[UnencryptedRange]:
    """
    AV1: OBU header, optional extension, optional LEB128 size unencrypted; payload encrypted.

    OBU types 2, 8, 15 (temporal delimiter, tile list, padding) are skipped.

    Args:
        frame (bytes): AV1 frame (OBU stream).

    Returns:
        list[UnencryptedRange]: One range per OBU for header/extension/size.
    """
    ranges: list[UnencryptedRange] = []
    pos = 0
    n = len(frame)
    while pos < n:
        if pos + 1 > n:
            break
        obu_start = pos
        obu_header = frame[pos]
        obu_type = (obu_header >> 3) & 0x0F
        obu_has_extension = (obu_header & 4) != 0
        obu_has_size_field = (obu_header & 2) != 0
        pos += 1
        if obu_has_extension:
            if pos + 1 > n:
                break
            pos += 1
        payload_len = 0
        if obu_has_size_field:
            if pos >= n:
                break
            payload_len, pos = _leb128_decode(frame, pos)
        unencrypted_len = pos - obu_start
        if obu_type in AV1_OBU_DROP_TYPES:
            pos = pos + payload_len if obu_has_size_field else n
            continue
        ranges.append(UnencryptedRange(offset=obu_start, length=unencrypted_len))
        pos = pos + payload_len if obu_has_size_field else n
    return ranges


def transform_av1_frame_for_encrypt(frame: bytes) -> bytes:
    """
    Transform AV1 frame for DAVE encryption (protocol.md AV1 section).

    - Drops OBU types 2 (TEMPORAL_DELIMITER), 8 (TILE_LIST), 15 (PADDING).
    - Reduces padded LEB128 OBU sizes to minimal encoding.
    - For the last OBU: sets obu_has_size_field to 0 and removes LEB128 size.

    Args:
        frame (bytes): Raw AV1 frame (OBU stream).

    Returns:
        bytes: Transformed frame suitable for encryption and supplemental footer.
    """
    n = len(frame)
    pos = 0
    # (header_byte, ext_off, ext_len, payload_off, payload_len, had_size_field)
    obus: list[tuple[int, int, int, int, int, bool]] = []
    while pos < n:
        if pos + 1 > n:
            break
        obu_header = frame[pos]
        obu_type = (obu_header >> 3) & 0x0F
        obu_has_extension = (obu_header & 4) != 0
        obu_has_size_field = (obu_header & 2) != 0
        pos += 1
        ext_off = pos
        ext_len = 1 if obu_has_extension else 0
        if obu_has_extension and pos + 1 <= n:
            pos += 1
        payload_len = 0
        if obu_has_size_field and pos < n:
            payload_len, size_end = _leb128_decode(frame, pos)
            pos = size_end
        payload_off = pos
        if obu_has_size_field:
            pos = pos + payload_len
        else:
            payload_len = n - payload_off
            pos = n
        if obu_type in AV1_OBU_DROP_TYPES:
            continue
        obus.append((obu_header, ext_off, ext_len, payload_off, payload_len, obu_has_size_field))
    if not obus:
        return frame
    out: list[bytes] = []
    for i, (header_byte, ext_off, ext_len, payload_off, actual_payload_len, _had_size) in enumerate(
        obus
    ):
        is_last = i == len(obus) - 1
        payload = frame[payload_off : payload_off + actual_payload_len]
        if is_last:
            new_header = header_byte & 0xFD
            out.append(bytes([new_header]))
            if ext_len:
                out.append(frame[ext_off : ext_off + ext_len])
            out.append(payload)
        else:
            out.append(bytes([header_byte]))
            if ext_len:
                out.append(frame[ext_off : ext_off + ext_len])
            out.append(_leb128_encode_minimal(actual_payload_len))
            out.append(payload)
    return b"".join(out)
