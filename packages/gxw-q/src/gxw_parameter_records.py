"""Bounded, lossless Param.wpa record framing and experimental ASCII names.

This module operates on one extracted stream, not a GXW project. It does not
identify a CPU, synchronize project metadata, or establish native acceptance.
Unknown records remain opaque and ordered. No file or GUI operations occur.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 4096
TERMINATOR = b"\xff\xff"


@dataclass(frozen=True)
class Record:
    tag: int
    payload: bytes


def encode_records(records: tuple[Record, ...]) -> bytes:
    """Encode ordered opaque records; lengths include the four-byte header."""
    if not isinstance(records, tuple) or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("expected a nonempty bounded record tuple")
    chunks = []
    total = 2
    for record in records:
        if not isinstance(record, Record) or type(record.tag) is not int:
            raise ValueError("invalid record")
        if not 0 <= record.tag <= 0xffff or type(record.payload) is not bytes:
            raise ValueError("invalid tag or payload")
        size = len(record.payload) + 4
        if size > 0xfffe or size % 2:
            raise ValueError("record length must be even and fit below the terminator")
        total += size
        if total > MAX_BYTES:
            raise ValueError("parameter byte budget exceeded")
        chunks.append(struct.pack("<HH", size, record.tag) + record.payload)
    return b"".join(chunks) + TERMINATOR


def decode_records(data: bytes) -> tuple[Record, ...]:
    """Reject truncation, trailing bytes and budget overflow; preserve payloads."""
    if type(data) is not bytes or not 6 <= len(data) <= MAX_BYTES:
        raise ValueError("invalid parameter byte input")
    offset = 0
    records = []
    while offset < len(data):
        if data[offset:offset + 2] == TERMINATOR:
            if offset + 2 != len(data) or not records:
                raise ValueError("unexpected terminator or trailing bytes")
            return tuple(records)
        if len(records) >= MAX_RECORDS or offset + 4 > len(data):
            raise ValueError("record budget exceeded or truncated header")
        size, tag = struct.unpack_from("<HH", data, offset)
        if size < 4 or size % 2 or offset + size > len(data):
            raise ValueError("invalid record length")
        records.append(Record(tag, data[offset + 4:offset + size]))
        offset += size
    raise ValueError("missing final terminator")


def _name_records(data: bytes) -> tuple[Record, ...]:
    records = decode_records(data)
    # Framing signatures are necessary but do not independently identify a CPU.
    if (records[0].tag != 0x0122 or len(records[0].payload) != 60
            or records[-1] != Record(0xfe00, b"\x28\x00")):
        raise ValueError("unrecognized experimental parameter envelope")
    tags = [record.tag for record in records]
    if any(tags.count(tag) > 1 for tag in (0, 1)):
        raise ValueError("ambiguous PLC name records")
    expected = [tag for tag in (0, 1) if tag in tags]
    if tags[1:1 + len(expected)] != expected:
        raise ValueError("unexpected PLC name record order")
    return records


def _ascii_text(payload: bytes) -> str:
    if not payload or payload[0] == 0:
        raise ValueError("empty text must be represented by an absent record")
    length = payload[0]
    end = length + 1
    padding = b"\xff" if end % 2 else b""
    if len(payload) != end + len(padding) or payload[end:] != padding:
        raise ValueError("invalid text length or padding")
    text = payload[1:end]
    if any(value < 0x20 or value > 0x7e for value in text):
        raise ValueError("only printable ASCII text is understood")
    return text.decode("ascii")


def decode_ascii_names(data: bytes) -> dict[str, str]:
    """Read Label/Comment only in the observed envelope; fail on unknown encoding."""
    records = _name_records(data)
    result = {"label": "", "comment": ""}
    for record in records:
        if record.tag in (0, 1):
            result["label" if record.tag == 0 else "comment"] = _ascii_text(record.payload)
    if len(result["label"]) > 8:
        raise ValueError("label exceeds the experimental eight-byte bound")
    return result


def replace_ascii_label(data: bytes, label: str) -> bytes:
    """Return a candidate stream; preserve every other record byte-for-byte.

    The conservative write subset is zero to eight ASCII letters, digits or
    underscores. This is a research bound, not a vendor-wide field constraint.
    The caller must independently authorize/profile the project and update its
    container metadata. This function never writes a project file.
    """
    if not isinstance(label, str) or re.fullmatch(r"[A-Za-z0-9_]{0,8}", label) is None:
        raise ValueError("label is outside the experimental ASCII subset")
    decode_ascii_names(data)
    records = tuple(record for record in _name_records(data) if record.tag != 0)
    if label:
        raw = label.encode("ascii")
        payload = bytes([len(raw)]) + raw
        if len(payload) % 2:
            payload += b"\xff"
        records = records[:1] + (Record(0, payload),) + records[1:]
    return encode_records(records)
