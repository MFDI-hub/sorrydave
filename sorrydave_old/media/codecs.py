"""
Codec-aware unencrypted range parsers for DAVE frame transform.

Supported codecs and plaintext ranges (matching libdave / davey):
    OPUS, VP9: full frame encrypted (no unencrypted ranges).
    VP8: first 1 byte (delta) or 10 bytes (key frame), per P bit in first byte.
    H264/H265: 4-byte start codes always unencrypted; see transform_h26x_frame_for_encrypt.
    AV1: OBU header, optional extension, optional LEB128 size; payload encrypted; OBU types 2, 8, 15 skipped.
    Unknown codec: empty list (entire frame encrypted).
"""

from __future__ import annotations

from sorrydave.types import UnencryptedRange

# VP8 payload header per RFC 7741: P is inverse key frame (bit 0 of first byte)
VP8_HEADER_KEYFRAME_LEN = 10
VP8_HEADER_DELTA_LEN = 1

# H264: NAL unit type in low 5 bits of first byte.
# davey treats only slice (1) and IDR (5) as VCL payload-encrypt; other types stay plaintext.
H264_NAL_TYPE_SLICE = 1
H264_NAL_TYPE_IDR = 5
H264_VCL_TYPES = frozenset({H264_NAL_TYPE_SLICE, H264_NAL_TYPE_IDR})
H264_NAL_HEADER_LEN = 1
# H265: NAL unit type in (first_byte & 0x7E) >> 1; VCL = 0-31, non-VCL = 32-63
H265_NAL_HEADER_LEN = 2
H265_NAL_TYPE_VCL_CUTOFF = 32
NALU_SHORT_START_SEQUENCE_SIZE = 3
NALU_LONG_START_CODE = b"\x00\x00\x00\x01"
# AV1: OBU types dropped by packetizer (protocol.md)
AV1_OBU_DROP_TYPES = frozenset({2, 8, 15})  # TEMPORAL_DELIMITER, TILE_LIST, PADDING


def get_unencrypted_ranges(frame: bytes, codec: str) -> list[UnencryptedRange]:
    """
    Return unencrypted byte ranges for the given codec and frame.

    Used by FrameEncryptor and FrameDecryptor. Codec name is case-insensitive.
    Supported: OPUS, VP9, VP8, H264/H.264, H265/HEVC, AV1. Unknown codec or
    parse error returns [] (full frame encrypted).

    For H264/H265, ranges are relative to the frame after 4-byte start-code
    rewrite (see transform_h26x_frame_for_encrypt). Callers that encrypt must
    use that transformed frame with these ranges.

    Args:
        frame (bytes): Encoded media frame.
        codec (str): Codec name (e.g. "OPUS", "VP8", "H264", "AV1").

    Returns:
        list[UnencryptedRange]: Ranges to leave plaintext; empty means encrypt entire frame.
    """
    codec_upper = codec.strip().upper() if codec else ""
    if codec_upper == "OPUS" or codec_upper == "VP9":
        return []
    if codec_upper == "VP8":
        return _vp8_unencrypted_ranges(frame)
    if codec_upper in ("H264", "H.264"):
        return transform_h26x_frame_for_encrypt(frame, h265=False)[1]
    if codec_upper in ("H265", "H265/HEVC", "HEVC"):
        return transform_h26x_frame_for_encrypt(frame, h265=True)[1]
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
    length = min(VP8_HEADER_KEYFRAME_LEN, len(frame)) if p_bit == 0 else VP8_HEADER_DELTA_LEN
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
    found = next_h26x_nalu_index(data, pos)
    if found is None:
        return len(data)
    nal_start, sc_len = found
    return nal_start - sc_len


def next_h26x_nalu_index(buffer: bytes, search_start_index: int) -> tuple[int, int] | None:
    """
    Find the next H.26x NAL unit.

    Returns (nal_unit_start_index, start_code_size) matching davey codec_utils.rs,
    or None if no start code remains.
    """
    if len(buffer) < NALU_SHORT_START_SEQUENCE_SIZE:
        return None
    i = search_start_index
    while i < len(buffer) - NALU_SHORT_START_SEQUENCE_SIZE:
        if buffer[i + 2] > 1:
            i += NALU_SHORT_START_SEQUENCE_SIZE
        elif buffer[i + 1] != 0:
            i += 2
        elif buffer[i] != 0 or buffer[i + 2] != 1:
            i += 1
        else:
            nal_unit_start_index = i + NALU_SHORT_START_SEQUENCE_SIZE
            if i >= 1 and buffer[i - 1] == 0:
                return nal_unit_start_index, 4
            return nal_unit_start_index, 3
    return None


def bytes_covering_h264_pps(payload: bytes, size_remaining: int) -> int:
    """
    Bytes of H264 slice payload that must stay unencrypted so the depacketizer
    can read first_mb_in_slice, sps_id, and pps_id (exp-golomb, RBSP-aware).

    Port of davey ``bytes_covering_h264_pps``.
    """
    emulation_prevention_byte = 0x03
    payload_bit_index = 0
    zero_bit_count = 0
    parsed_exp_golomb_values = 0
    limit = size_remaining * 8
    while payload_bit_index < limit and parsed_exp_golomb_values < 3:
        bit_index = payload_bit_index % 8
        byte_index = payload_bit_index // 8
        if byte_index >= len(payload):
            break
        payload_byte = payload[byte_index]
        if (
            bit_index == 0
            and byte_index >= 2
            and payload_byte == emulation_prevention_byte
            and payload[byte_index - 1] == 0
            and payload[byte_index - 2] == 0
        ):
            payload_bit_index += 8
            continue
        if (payload_byte & (1 << (7 - bit_index))) == 0:
            zero_bit_count += 1
            payload_bit_index += 1
            if zero_bit_count >= 32:
                return 0
        else:
            parsed_exp_golomb_values += 1
            payload_bit_index = payload_bit_index + 1 + zero_bit_count
            zero_bit_count = 0
    result = (payload_bit_index // 8) + 1
    return result if result <= 0xFFFF else 0


class _H26xRangeBuilder:
    """Rebuild an H.26x frame with 4-byte start codes and merged unencrypted ranges."""

    def __init__(self) -> None:
        self.frame_index = 0
        self.out = bytearray()
        self.ranges: list[UnencryptedRange] = []

    def add_unencrypted(self, data: bytes) -> None:
        if not data:
            return
        if self.ranges and self.ranges[-1].offset + self.ranges[-1].length == self.frame_index:
            last = self.ranges[-1]
            self.ranges[-1] = UnencryptedRange(last.offset, last.length + len(data))
        else:
            self.ranges.append(UnencryptedRange(self.frame_index, len(data)))
        self.out.extend(data)
        self.frame_index += len(data)

    def add_encrypted(self, data: bytes) -> None:
        self.out.extend(data)
        self.frame_index += len(data)


def transform_h26x_frame_for_encrypt(
    frame: bytes, *, h265: bool
) -> tuple[bytes, list[UnencryptedRange]]:
    """
    Rewrite H.26x Annex B start codes to 4 bytes and compute davey unencrypted ranges.

    Returns (transformed_frame, ranges). On parse failure, returns the original
    frame with no unencrypted ranges (full encrypt).
    """
    header_len = H265_NAL_HEADER_LEN if h265 else H264_NAL_HEADER_LEN
    if len(frame) < NALU_SHORT_START_SEQUENCE_SIZE + header_len:
        return frame, []
    builder = _H26xRangeBuilder()
    nalu = next_h26x_nalu_index(frame, 0)
    while nalu is not None:
        nal_unit_start_index, _sc_len = nalu
        if nal_unit_start_index >= len(frame) - 1:
            break
        builder.add_unencrypted(NALU_LONG_START_CODE)
        next_nalu = next_h26x_nalu_index(frame, nal_unit_start_index)
        next_nalu_start = len(frame) if next_nalu is None else next_nalu[0] - next_nalu[1]
        if h265:
            nal_type = (frame[nal_unit_start_index] & 0x7E) >> 1
            if nal_type < H265_NAL_TYPE_VCL_CUTOFF:
                hdr_end = min(
                    nal_unit_start_index + H265_NAL_HEADER_LEN, next_nalu_start
                )
                builder.add_unencrypted(frame[nal_unit_start_index:hdr_end])
                builder.add_encrypted(frame[hdr_end:next_nalu_start])
            else:
                builder.add_unencrypted(frame[nal_unit_start_index:next_nalu_start])
        else:
            nal_type = frame[nal_unit_start_index] & 0x1F
            if nal_type in (H264_NAL_TYPE_SLICE, H264_NAL_TYPE_IDR):
                payload_start = nal_unit_start_index + H264_NAL_HEADER_LEN
                pps_bytes = bytes_covering_h264_pps(
                    frame[payload_start:], len(frame) - payload_start
                )
                unenc_end = min(payload_start + pps_bytes, next_nalu_start)
                builder.add_unencrypted(frame[nal_unit_start_index:unenc_end])
                builder.add_encrypted(frame[unenc_end:next_nalu_start])
            else:
                builder.add_unencrypted(frame[nal_unit_start_index:next_nalu_start])
        nalu = next_nalu
    if builder.frame_index == 0:
        return frame, []
    return bytes(builder.out), builder.ranges


def _h264_unencrypted_ranges(frame: bytes) -> list[UnencryptedRange]:
    """H264 unencrypted ranges on the 4-byte-start-code rewritten frame."""
    return transform_h26x_frame_for_encrypt(frame, h265=False)[1]


def _h265_unencrypted_ranges(frame: bytes) -> list[UnencryptedRange]:
    """H265 unencrypted ranges on the 4-byte-start-code rewritten frame."""
    return transform_h26x_frame_for_encrypt(frame, h265=True)[1]


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
