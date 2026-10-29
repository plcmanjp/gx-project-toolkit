"""Read-only bounded parameter framing and observed ASCII-name decoding.

Unknown records remain opaque. No encoder or project mutation is exposed.
Envelope observations do not authenticate CPU, ownership or native encoding.
"""
from __future__ import annotations
from dataclasses import dataclass
import struct

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 4096
TERMINATOR = b"\xff\xff"

@dataclass(frozen=True)
class Record:
    tag: int
    payload: bytes


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
