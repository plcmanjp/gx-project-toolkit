"""Bounded read-only GXW snapshot analysis, schema 1.

Input: immutable CFB bytes, or an SHA-pinned allow-root file snapshot.
Output: canonical JSON-compatible observations with opaque locators and PARTIAL
coverage. No writes, GUI, PLC, official validation, or OS resource sandbox.
Dependencies: existing bounded OLE/XML, ladder, Reference IR and Param readers.
Run: python -B -m gxw_project_analysis inspect FILE --sha256 HEX --allow-root DIR
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys

import gxw_bounded_ole as bounded
import gxw_bounded_xml as xml
import gxw_ladder_reader as reader
import gxw_reference_ir as reference
import gxw_parameter_reader as parameters

SCHEMA = "plcman.gxw.project-analysis/1"
PROFILE = "mitsubishi.gxw.q.observed-read-only/1"
INVENTORY_SCHEMA = "plcman.gxw.project-inventory/1"
MAX_REGISTRY_TOKENS = 4096


class AnalysisError(ValueError):
    """A stable, privacy-safe fail-closed reason code."""


@dataclass(frozen=True)
class Policy:
    max_input_bytes: int = 16 * 1024 * 1024
    max_stream_bytes: int = 4 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_streams: int = 1024
    max_rows: int = 20000
    max_response_bytes: int = 8 * 1024 * 1024
    include_text: bool = False

    def __post_init__(self):
        ceilings = (16*1024*1024, 4*1024*1024, 32*1024*1024, 1024, 20000, 8*1024*1024)
        for name, ceiling in zip(tuple(self.__dataclass_fields__)[:-1], ceilings):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise AnalysisError("INVALID_POLICY_" + name.upper())
        if type(self.include_text) is not bool:
            raise AnalysisError("INVALID_POLICY_INCLUDE_TEXT")


def _policy(policy):
    if type(policy) is not Policy:
        raise AnalysisError("POLICY_REQUIRED")
    policy.__post_init__()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(result):
    return json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _bounded_result(result, policy):
    payload = canonical_json(result)
    if len(payload.encode("ascii")) > policy.max_response_bytes:
        raise AnalysisError("RESPONSE_LIMIT")
    # Do not expose the cached engine identity through a mutable result alias.
    return json.loads(payload)


def _identity():
    modules = (sys.modules[__name__], bounded, xml, reader, reference, parameters,
               reference.legacy)
    return {"schema": SCHEMA, "policy_schema": 1,
            "modules": {("gxw_project_analysis" if m is sys.modules[__name__] else m.__name__):
                        _sha(Path(m.__file__).read_bytes()) for m in modules},
            "olefile_version": str(bounded.olefile.__version__)}


# Code identity is captured once; no Git, project path or private-state queries.
ENGINE = _identity()


def _path_chain(path):
    chain = list(reversed(path.parents)) + [path]
    result = []
    for item in chain:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AnalysisError("PATH_LINK_OR_REPARSE_POINT")
        # Directory timestamps, size and link counts change when unrelated
        # siblings are created. Bind ancestors by replacement identity only;
        # retain full mutation checks for the leaf and the opened descriptor.
        identity = ((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                    if item != path else _stat_id(info))
        result.append((str(item), identity))
    return result


def _stat_id(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _safe_path(value):
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or raw.startswith(("\\\\", "//")):
        raise AnalysisError("PATH_UNC_OR_INVALID")
    path = Path(raw)
    if any(part in ("..", ".") for part in re.split(r"[\\/]", raw)):
        raise AnalysisError("PATH_TRAVERSAL")
    if ":" in raw[len(path.drive):] or "\x00" in raw:
        raise AnalysisError("PATH_ADS_OR_INVALID")
    return Path(os.path.abspath(path))


def _open_readonly(path):
    if os.name != "nt":
        return os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    # Deny concurrent write/delete handles while the snapshot is captured.
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    handle = create(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise AnalysisError("SNAPSHOT_OPEN_DENIED")
    try:
        final = kernel.GetFinalPathNameByHandleW
        final.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
        final.restype = wintypes.DWORD
        buf = ctypes.create_unicode_buffer(32768)
        n = final(handle, buf, len(buf), 0)
        if not 0 < n < len(buf) or os.path.normcase(buf.value.removeprefix("\\\\?\\")) != os.path.normcase(str(path)):
            raise AnalysisError("SNAPSHOT_HANDLE_PATH_MISMATCH")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None
        return fd
    finally:
        if handle is not None:
            close = kernel.CloseHandle
            close.argtypes = (wintypes.HANDLE,)
            close(handle)


def capture_file(path, *, expected_sha256, allow_root, policy=Policy()):
    """Read once under an explicit root and expected digest; return fixed bytes.

    Reject links/reparse points in every ancestor, ADS, UNC, traversal, hardlinks,
    nonregular files, changes in descriptor/path identity and size/digest mismatch.
    Windows additionally denies writers/deletion and verifies the opened path.
    This is not an OS-level time/memory sandbox.
    """
    _policy(policy)
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is None:
        raise AnalysisError("EXPECTED_SHA256_REQUIRED")
    if allow_root is None:
        raise AnalysisError("ALLOW_ROOT_REQUIRED")
    try:
        source, root = _safe_path(path), _safe_path(allow_root)
        if source == root or not source.is_relative_to(root):
            raise AnalysisError("PATH_OUTSIDE_ALLOW_ROOT")
        if not root.is_dir():
            raise AnalysisError("ALLOW_ROOT_NOT_DIRECTORY")
        before_chain = _path_chain(source)
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AnalysisError("INPUT_NOT_SINGLE_REGULAR_FILE")
        if not 0 < before.st_size <= policy.max_input_bytes:
            raise AnalysisError("INPUT_SIZE_LIMIT")
        fd = _open_readonly(source)
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            opened_id, path_id = _stat_id(opened), _stat_id(before)
            # CPython Windows path stat exposes creation time in st_ctime;
            # descriptor fstat exposes change time. Compare shared fields here,
            # then retain both full identities in their respective postchecks.
            if os.name == "nt":
                opened_id = opened_id[:5] + opened_id[6:]
                path_id = path_id[:5] + path_id[6:]
            if opened_id != path_id:
                raise AnalysisError("SNAPSHOT_IDENTITY_CHANGED")
            body = handle.read(policy.max_input_bytes + 1)
            if (_stat_id(os.fstat(handle.fileno())) != _stat_id(opened)
                    or _path_chain(source) != before_chain or len(body) != opened.st_size):
                raise AnalysisError("SNAPSHOT_IDENTITY_CHANGED")
        if _sha(body) != expected_sha256.lower():
            raise AnalysisError("SHA256_MISMATCH")
        return body
    except AnalysisError:
        raise
    except (OSError, ValueError, TypeError):
        raise AnalysisError("SNAPSHOT_PATH_OR_IO_REJECTED") from None


def _cfb_preflight(data, policy, *, outer_project=False):
    """Validate allocation graphs before olefile traverses directory/stream chains.

    Reject cycles, shared sectors, out-of-range and overdeclared chains, including
    mini streams. Allocation bytes are structural only; no command decoder here.
    """
    FREE, END, FAT, DIF = 0xffffffff, 0xfffffffe, 0xfffffffd, 0xfffffffc
    if len(data) < 512 or data[:8] != bytes.fromhex("d0cf11e0a1b11ae1"):
        raise AnalysisError("NOT_CFB")
    u16 = lambda off: struct.unpack_from("<H", data, off)[0]
    u32 = lambda off: struct.unpack_from("<I", data, off)[0]
    version, shift = u16(26), u16(30)
    if (version, shift) not in ((3, 9), (4, 12)) or u16(28) != 0xfffe or u16(32) != 6 or u32(56) != 4096:
        raise AnalysisError("CFB_HEADER_UNSUPPORTED")
    sector = 1 << shift
    if len(data) % sector or len(data) < sector * 2:
        raise AnalysisError("CFB_TRUNCATED")
    count = len(data)//sector - 1
    def block(index):
        if not 0 <= index < count:
            raise AnalysisError("CFB_SECTOR_OUT_OF_RANGE")
        return data[(index+1)*sector:(index+2)*sector]
    def words(body):
        return list(struct.unpack("<" + "I"*(len(body)//4), body))
    fat_ids = [v for v in words(data[76:512]) if v != FREE]
    dif_ids, next_dif = [], u32(68)
    if u32(72) > count:
        raise AnalysisError("CFB_DIFAT_LIMIT")
    for _ in range(u32(72)):
        if next_dif in dif_ids:
            raise AnalysisError("CFB_ALLOCATION_CYCLE")
        dif_ids.append(next_dif)
        entries = words(block(next_dif))
        fat_ids.extend(v for v in entries[:-1] if v != FREE)
        next_dif = entries[-1]
    if next_dif not in (END, FREE) or len(fat_ids) != u32(44) or len(set(fat_ids+dif_ids)) != len(fat_ids+dif_ids):
        raise AnalysisError("CFB_DIFAT_INVALID")
    fat = [v for i in fat_ids for v in words(block(i))]
    if len(fat) < count:
        raise AnalysisError("CFB_FAT_TRUNCATED")
    for i in fat_ids:
        if fat[i] != FAT:
            raise AnalysisError("CFB_FAT_INVALID")
    for i in dif_ids:
        if fat[i] != DIF:
            raise AnalysisError("CFB_DIFAT_INVALID")
    def graph(table, capacity):
        done = set()
        for start in range(min(len(table), capacity)):
            current, seen = start, set()
            while current not in (FREE, END, FAT, DIF) and current not in done:
                if not 0 <= current < capacity or current >= len(table):
                    raise AnalysisError("CFB_SECTOR_OUT_OF_RANGE")
                if current in seen:
                    raise AnalysisError("CFB_ALLOCATION_CYCLE")
                seen.add(current)
                current = table[current]
            done.update(seen)
    graph(fat, count)
    owned = set(fat_ids + dif_ids)
    def chain(start, table, capacity, used):
        indexes = []
        while start != END:
            if not 0 <= start < capacity or start >= len(table) or start in used:
                raise AnalysisError("CFB_CHAIN_CYCLE_OR_OVERLAP")
            used.add(start)
            indexes.append(start)
            start = table[start]
        return indexes
    def big(start, size=None):
        ids = chain(start, fat, count, owned)
        if size is not None and len(ids) != math.ceil(size/sector):
            raise AnalysisError("CFB_DECLARED_SIZE_MISMATCH")
        return b"".join(block(i) for i in ids)
    directory = big(u32(48))
    if len(directory)//128 > policy.max_streams * 4 + 4:
        raise AnalysisError("CFB_DIRECTORY_LIMIT")
    entries = [directory[i:i+128] for i in range(0, len(directory), 128)]
    if not entries or entries[0][66] != 5:
        raise AnalysisError("CFB_ROOT_INVALID")
    mini_count = u32(64)
    if mini_count > count:
        raise AnalysisError("CFB_MINIFAT_LIMIT")
    mini_raw = big(u32(60), mini_count*sector) if mini_count else b""
    if not mini_count and u32(60) not in (END, FREE):
        raise AnalysisError("CFB_MINIFAT_INVALID")
    mini_fat = words(mini_raw)
    root_size = struct.unpack_from("<Q", entries[0], 120)[0]
    if root_size > policy.max_total_bytes:
        raise AnalysisError("CFB_ROOT_SIZE_LIMIT")
    big(struct.unpack_from("<I", entries[0], 116)[0], root_size)
    mini_capacity = math.ceil(root_size/64)
    graph(mini_fat, mini_capacity)
    seen, direct_children = {0}, set()
    pending = [(struct.unpack_from("<I", entries[0], 76)[0], True)]
    while pending:
        index, root_level = pending.pop()
        if index == FREE:
            continue
        if index in seen or not 0 < index < len(entries):
            raise AnalysisError("CFB_DIRECTORY_CYCLE_OR_ALIAS")
        seen.add(index)
        entry = entries[index]
        if entry[66] not in (1, 2):
            raise AnalysisError("CFB_DIRECTORY_TYPE")
        if root_level:
            direct_children.add(index)
        left, right, child = struct.unpack_from("<III", entry, 68)
        pending.extend(((left, root_level), (right, root_level), (child, False)))
    minis, total, streams = set(), 0, 0
    for index in sorted(seen - {0}):
        entry = entries[index]
        if entry[66] != 2:
            continue
        streams += 1
        size = struct.unpack_from("<Q", entry, 120)[0]
        start = struct.unpack_from("<I", entry, 116)[0]
        total += size
        # Only the outer project's root-level _hdb is a container of streams.
        # Its bytes remain bounded by the input cap; contained data streams
        # receive the ordinary stream cap during the separate nested preflight.
        hdb_name = "_hdb\0".encode("utf-16le")
        carrier = (outer_project and index in direct_children
                   and struct.unpack_from("<H", entry, 64)[0] == len(hdb_name)
                   and entry[:len(hdb_name)] == hdb_name)
        stream_limit = policy.max_input_bytes if carrier else policy.max_stream_bytes
        if streams > policy.max_streams or size > stream_limit or total > policy.max_total_bytes:
            raise AnalysisError("CFB_STREAM_BUDGET")
        if size >= 4096:
            big(start, size)
        elif size:
            if len(chain(start, mini_fat, mini_capacity, minis)) != math.ceil(size/64):
                raise AnalysisError("CFB_DECLARED_SIZE_MISMATCH")
        elif start not in (END, FREE, 0):
            raise AnalysisError("CFB_EMPTY_STREAM_INVALID")


def _streams(data, policy, *, outer_project=False):
    _cfb_preflight(data, policy, outer_project=outer_project)
    try:
        ole = bounded.open_nested(data)
        try:
            streams = bounded.all_streams(ole)
            if ole.parsing_issues:
                raise AnalysisError("CFB_PARSER_DEFECT")
            return streams
        finally:
            ole.close()
    except AnalysisError:
        raise
    except Exception:
        raise AnalysisError("CFB_PARSE_REJECTED") from None


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _registry(streams, policy):
    """Bound registry tokens before the legacy decoder materializes its lists.

    The legacy decoder uses a linear regex scan, set-backed deduplication and
    bounded-name validation. This structural preflight bounds its intermediate
    token/name lists too; it does not replace registry selection or name rules.
    Exact token counts avoid one full byte search per decoded name.
    """
    limit = min(MAX_REGISTRY_TOKENS, policy.max_rows)
    token_total, selected, repeated = 0, None, False
    for key, body in sorted(streams.items()):
        if not body.startswith(b"\xff\xff\xff\xff"):
            continue
        counts = Counter()
        for match in re.finditer(rb"(?:[\x20-\x7e]\x00){2,}", body):
            token_total += 1
            if token_total > limit:
                raise AnalysisError("POU_REGISTRY_TOKEN_LIMIT")
            # Longer runs cannot be valid names under the existing validator.
            if match.end() - match.start() <= 64:
                name = match.group().decode("utf-16le")
                if reader.is_valid_pou_name(name):
                    counts[name] += 1
        candidate = reader.parse_pou_registry({key: body})
        if candidate is None:
            continue
        if len(candidate[2]) > limit:
            raise AnalysisError("POU_REGISTRY_NAME_LIMIT")
        if selected is not None:
            raise AnalysisError("POU_REGISTRY_AMBIGUOUS")
        selected = candidate
        repeated = any(count > 1 for count in counts.values())
    return selected, repeated


def _mapping(top, nested, aliases, policy):
    if "projectdatalist.xml" not in top:
        raise AnalysisError("GXW_METADATA_REQUIRED")
    try:
        root = xml.parse_xml(top["projectdatalist.xml"])
    except ValueError:
        raise AnalysisError("GXW_XML_METADATA_REJECTED") from None
    result, ids, names = [], set(), set()
    for entry in (node for node in root.iter() if _local(node.tag) == "D_Projectdata"):
        fields = {}
        for field in ("iID", "szName"):
            values = [c.text or "" for c in entry if _local(c.tag) == field]
            if len(values) != 1 or not values[0]:
                raise AnalysisError("METADATA_FIELD_AMBIGUOUS")
            fields[field] = values[0]
        ident, name = fields["iID"], fields["szName"]
        if not re.fullmatch(r"0|[1-9][0-9]{0,9}", ident):
            raise AnalysisError("METADATA_ID_INVALID")
        if ident in ids or name.casefold() in names:
            raise AnalysisError("METADATA_MAPPING_AMBIGUOUS")
        ids.add(ident)
        names.add(name.casefold())
        targets = (["_hdb/" + ident] if ident in nested else []) + ([name] if name in top else [])
        if len(targets) > 1:
            raise AnalysisError("METADATA_TARGET_AMBIGUOUS")
        result.append({"id": ident, "name": name if policy.include_text else None,
                       "name_sha256": _sha(name.encode()),
                       "member": aliases[targets[0]] if targets else None,
                       "role": "pou_resource" if name.endswith(".res") else
                               "pou_program" if name.endswith(".Program.pou") else
                               "parameter" if name == "Param.wpa" else "opaque",
                       "state": "MAPPED" if targets else "UNRESOLVED"})
    if not result:
        raise AnalysisError("GXW_METADATA_MAPPING_EMPTY")
    return result, []


def _project_pou_text(body, rows, *, pou, member, pou_order, include_text):
    """Project legacy statement and note rows with default typed helpers only.

    ValueError from a helper retains every row of that kind as UNRESOLVED.
    Display text follows include_text; hashes stay pre-redaction. Note
    attachments are {sequence, opcode} and never carry operands.
    """
    statement_rows, note_rows, preceding_nontext = set(), [], {}
    previous = None
    for index, row in enumerate(rows):
        opcode = row[0]
        if opcode == "__STMT__":
            statement_rows.add(index)
        elif opcode == "__NOTE__":
            note_rows.append(index)
            preceding_nontext[index] = previous
        else:
            previous = (index, opcode)
    if not statement_rows and not note_rows:
        return [], [], []
    # CP1252 is the helper default, not an authenticated source code page.
    unknowns = ["POU_TEXT_ENCODING_UNVERIFIED"]

    def emit(sequence, kind, *, state, text, text_sha256, hash_basis, raw_type,
             subtype, source_step_width, attachment):
        return {"pou": pou, "member": member, "sequence": sequence, "kind": kind,
                "state": state, "text": text if include_text else None,
                "text_sha256": text_sha256, "hash_basis": hash_basis,
                "raw_type": raw_type, "subtype": subtype,
                "source_step_width": source_step_width, "attachment": attachment}

    def observed(item, sequence, kind, attachment):
        if "text" not in item or "raw_text_hex" not in item:
            raise ValueError("typed text source unavailable")
        return emit(sequence, kind, state="OBSERVED_SOURCE", text=item["text"],
                    text_sha256=_sha(bytes.fromhex(item["raw_text_hex"])),
                    hash_basis="SOURCE_BYTES", raw_type=item.get("raw_type"),
                    subtype=item.get("subtype"),
                    source_step_width=item.get("source_step_width"), attachment=attachment)

    statements = None
    if statement_rows:
        try:
            bound = {}
            for item in reader.typed_statement_records(body):
                if "row_index" not in item:
                    raise ValueError("typed Statement row binding mismatch")
                index = item["row_index"]
                if type(index) is not int or index not in statement_rows or index in bound:
                    raise ValueError("typed Statement row binding mismatch")
                bound[index] = observed(item, index, "statement", None)
            if len(bound) != len(statement_rows):
                raise ValueError("typed Statement frame count does not match decoded Statement row count")
            statements = bound
        except AnalysisError:
            raise
        except ValueError:
            unknowns.append("POU_STATEMENT_TYPE_OR_FRAMING_UNVERIFIED")

    notes = None
    if note_rows:
        try:
            typed = list(reader.typed_note_records(body))
            if len(typed) != len(note_rows):
                raise ValueError("typed Note frame count does not match decoded Note row count")
            bound, subtype_unverified = {}, False
            for item, index in zip(typed, note_rows):
                if item.get("text") != rows[index][1]:
                    raise ValueError("typed Note frame text does not match decoded Note row")
                preceding = preceding_nontext[index]
                if preceding is None:
                    raise ValueError("typed Note has no preceding instruction attachment")
                attachment = {"sequence": preceding[0], "opcode": preceding[1]}
                if item.get("subtype") is None:
                    subtype_unverified = True
                bound[index] = observed(item, index, "note", attachment)
            notes = bound
            if subtype_unverified:
                unknowns.append("POU_NOTE_SUBTYPE_UNVERIFIED")
        except AnalysisError:
            raise
        except ValueError:
            unknowns.append("POU_NOTE_TYPE_OR_ATTACHMENT_UNVERIFIED")

    records = []
    for index, row in enumerate(rows):
        if row[0] == "__STMT__":
            record = statements[index] if statements is not None else emit(
                index, "statement", state="UNRESOLVED", text=row[1],
                text_sha256=_sha(row[1].encode("utf-8")), hash_basis="DECODED_ROW_UTF8",
                raw_type=None, subtype=None, source_step_width=None, attachment=None)
        elif row[0] == "__NOTE__":
            record = notes[index] if notes is not None else emit(
                index, "note", state="UNRESOLVED", text=row[1],
                text_sha256=_sha(row[1].encode("utf-8")), hash_basis="DECODED_ROW_UTF8",
                raw_type=None, subtype=None, source_step_width=None, attachment=None)
        else:
            continue
        records.append(record)
    digest = [{"pou_order": pou_order, "sequence": record["sequence"], "kind": record["kind"],
               "text_sha256": record["text_sha256"], "hash_basis": record["hash_basis"],
               "raw_type": record["raw_type"], "subtype": record["subtype"],
               "source_step_width": record["source_step_width"],
               "attachment": None if record["attachment"] is None else {
                   "sequence": record["attachment"]["sequence"],
                   "opcode": record["attachment"]["opcode"]}}
              for record in records]
    return records, digest, unknowns


def _project_device_comments(nested, aliases, metadata, policy):
    """Project counted comment carriers from already bounded nested streams.

    Only a 1a000801 prefix is a candidate. The helper runs for one stream and
    only after a 60-byte header and 200a marker match. Bit comments are still
    materialized inside device_comment_pairs; this path does not decode them.
    """
    sources, records, digest = [], [], []
    unknowns = ["DEVICE_COMMENT_COMPLETENESS_UNVERIFIED", "DEVICE_COMMENT_SCOPE_UNVERIFIED",
                "DEVICE_COMMENT_NATIVE_ENCODING_UNVERIFIED", "DEVICE_COMMENT_LEGACY_CARRIERS_NOT_DECODED"]
    budget_messages = {"comment directory exceeds entry budget", "comment block exceeds entry budget"}
    observed, saw_candidate = 0, False

    def unresolved(member, metadata_bindings, binding, reason):
        unknowns.append(reason)
        sources.append({"member": member, "state": "UNRESOLVED", "record_count": None,
                        "metadata_bindings": metadata_bindings, "scope": "UNVERIFIED",
                        "encoding": None, "reason": reason})
        digest.append({"binding": binding, "state": "UNRESOLVED", "records": []})

    for key, body in sorted(nested.items()):
        if not body.startswith(bytes.fromhex("1a 00 08 01")):
            continue
        saw_candidate = True
        member = aliases["_hdb/" + key]
        bound = [row for row in metadata if row["member"] == member]
        metadata_bindings = len(bound)
        binding = sorted(row["name_sha256"] for row in bound)
        if metadata_bindings != 1:
            unknowns.append("DEVICE_COMMENT_METADATA_BINDING_UNVERIFIED")
        if len(body) < 60 or body[56:58] != bytes.fromhex("20 0a"):
            unresolved(member, metadata_bindings, binding, "DEVICE_COMMENT_FRAMING_UNVERIFIED")
            continue
        directory_end = 60 + 10 * struct.unpack_from("<H", body, 58)[0]
        if directory_end <= len(body):
            counted = 0
            for pos in range(60, directory_end, 10):
                counted += struct.unpack_from("<I", body, pos + 6)[0]
            if observed + counted > policy.max_rows:
                raise AnalysisError("DEVICE_COMMENT_LIMIT")
        try:
            outcome = reader.device_comment_pairs({key: body})
        except AnalysisError:
            raise
        except ValueError as error:
            if str(error) in budget_messages:
                raise AnalysisError("DEVICE_COMMENT_LIMIT") from None
            unresolved(member, metadata_bindings, binding, "DEVICE_COMMENT_PARSE_UNVERIFIED")
            continue
        valid = type(outcome) is tuple and len(outcome) == 2 and outcome[1] is None and type(outcome[0]) is list
        pairs = outcome[0] if valid else None
        seen = set()
        if valid:
            for item in pairs:
                if type(item) not in (tuple, list) or len(item) != 2:
                    valid = False
                    break
                device, text = item
                if type(device) is not str or type(text) is not str or device in seen:
                    valid = False
                    break
                seen.add(device)
        if not valid:
            unresolved(member, metadata_bindings, binding, "DEVICE_COMMENT_PARSE_UNVERIFIED")
            continue
        if observed + len(pairs) > policy.max_rows:
            raise AnalysisError("DEVICE_COMMENT_LIMIT")
        digest_records = []
        for sequence, (device, text) in enumerate(pairs):
            text_sha256 = _sha(text.encode("utf-16le"))
            digest_records.append({"sequence": sequence, "device": device,
                                   "text_sha256": text_sha256, "encoding": "utf-16le"})
            records.append({"member": member, "sequence": sequence, "device": device,
                            "text": text if policy.include_text else None,
                            "text_sha256": text_sha256, "encoding": "utf-16le",
                            "state": "OBSERVED_SOURCE"})
        sources.append({"member": member, "state": "OBSERVED_SOURCE", "record_count": len(pairs),
                        "metadata_bindings": metadata_bindings, "scope": "UNVERIFIED",
                        "encoding": "utf-16le", "reason": None})
        digest.append({"binding": binding, "state": "OBSERVED_SOURCE", "records": digest_records})
        observed += len(pairs)
    if not saw_candidate:
        unknowns.append("DEVICE_COMMENT_CARRIER_NOT_OBSERVED")
    digest.sort(key=canonical_json)
    projection = {"state": "PARTIAL", "scope": "COUNTED_CARRIER_OBSERVATIONS_ONLY",
                  "expected_total": None, "observed_records": len(records),
                  "sources": sources, "records": records}
    return projection, digest, unknowns


def _analyze(data, policy, *, inventory_only=False):
    _policy(policy)
    if type(data) is not bytes or not 0 < len(data) <= policy.max_input_bytes:
        raise AnalysisError("INPUT_BYTES_OR_SIZE_INVALID")
    try:
        top = _streams(data, policy, outer_project=True)
        if "_hdb" not in top:
            raise AnalysisError("GXW_HDB_REQUIRED")
        nested = _streams(top["_hdb"], policy)
        if set(top).intersection("_hdb/" + k for k in nested):
            raise AnalysisError("MEMBER_NAMESPACE_COLLISION")
        members = dict(top)
        members.update({"_hdb/" + k: v for k, v in nested.items()})
        if len(members) > policy.max_streams or sum(map(len, members.values())) > policy.max_total_bytes:
            raise AnalysisError("AGGREGATE_STREAM_BUDGET")
        aliases = {k: f"m{i:04d}" for i, k in enumerate(sorted(members))}
        metadata, unknowns = _mapping(top, nested, aliases, policy)
        inventory = [{"member": aliases[k], "path": k if policy.include_text else None,
                      "path_sha256": _sha(k.encode()), "bytes": len(v), "sha256": _sha(v)}
                     for k, v in sorted(members.items())]
        candidates = []
        for key, body in sorted(members.items()):
            # Literal observations only; no CPU authentication or default.
            for encoding, raw in (("ascii", body), ("utf16le", body[::2])):
                if encoding == "utf16le" and len(body) > policy.max_stream_bytes:
                    continue
                for hit in re.finditer(rb"(?<![A-Za-z0-9])(?:Q[0-9]{2}[A-Z]{1,8}(?:CPU)?)(?![A-Za-z0-9])", raw):
                    if encoding == "utf16le" and any(body[i] for i in range(hit.start()*2+1, min(hit.end()*2,len(body)),2)):
                        continue
                    candidates.append({"literal": hit.group().decode(), "member": aliases[key],
                                       "offset": hit.start()*(2 if encoding == "utf16le" else 1),
                                       "encoding": encoding, "state": "UNAUTHENTICATED_LITERAL"})
                    if len(candidates) > policy.max_rows:
                        raise AnalysisError("CPU_CANDIDATE_LIMIT")
        registry, repeated_registry_name = _registry(nested, policy)
        reg_names = set(registry[2]) if registry else None
        if repeated_registry_name:
            unknowns.append("POU_REGISTRY_REPEATED_NAME_AMBIGUOUS")
        found = {}
        for key, body in sorted(nested.items()):
            if reader.is_pou_body(body) and reg_names is not None and reader.find_pou_name(body) not in reg_names:
                unknowns.append("POU_BODY_OUTSIDE_REGISTRY")
            if reader.is_pou_body(body, reg_names):
                name = reader.find_pou_name(body)
                if name in found:
                    raise AnalysisError("POU_BODY_AMBIGUOUS")
                found[name] = (key, body)
        pous, row_total = [], 0
        text_records, text_digest = [], []
        for i, (name, (key, body)) in enumerate(sorted(found.items())):
            bindings = [m for m in metadata if m["member"] == aliases["_hdb/"+key] and m["role"] == "pou_resource"]
            if bindings and bindings[0]["name_sha256"] != _sha((name+".res").encode()):
                raise AnalysisError("POU_METADATA_NAME_MISMATCH")
            if not bindings:
                unknowns.append("POU_METADATA_BINDING_UNVERIFIED")
            if not any(m["name_sha256"] == _sha((name+".Program.pou").encode()) and m["member"] is not None for m in metadata):
                unknowns.append("POU_PROGRAM_ROLE_MISSING")
            visible = name if policy.include_text else f"p{i:04d}"
            if inventory_only:
                pous.append({"name": visible, "source_store": aliases["_hdb/"+key],
                             "source_digest": _sha(body), "bytes": len(body),
                             "name_sha256": _sha(name.encode())})
                continue
            # Bound decoder work by bytes before materializing rows as well as rows after.
            if len(body) > min(policy.max_stream_bytes, policy.max_rows*256):
                raise AnalysisError("POU_BYTE_BUDGET")
            rows, ui, ud = reader.pou_rows(body)
            if not reader.program_section(body).endswith(bytes.fromhex("04340204")):
                unknowns.append("POU_END_TRAILER_NOT_OBSERVED")
            row_total += len(rows)
            if row_total > policy.max_rows:
                raise AnalysisError("ROW_LIMIT")
            pous.append({"name": visible, "source_store": aliases["_hdb/"+key],
                         "source_digest": _sha(body), "rows": rows,
                         "unknown_instructions": sorted(ui), "unknown_devices": sorted(ud)})
            # Reference IR skips statement/note rows; keep a separate projection.
            projected, projected_digest, text_unknowns = _project_pou_text(
                body, rows, pou=visible, member=aliases["_hdb/"+key],
                pou_order=i, include_text=policy.include_text)
            text_records.extend(projected)
            text_digest.extend(projected_digest)
            unknowns.extend(text_unknowns)
        if not pous:
            unknowns.append("NO_RECOGNIZED_POU")
        if not registry:
            unknowns.append("POU_REGISTRY_MISSING")
        if any(m["state"] == "UNRESOLVED" for m in metadata):
            unknowns.append("METADATA_TARGET_MISSING")
        unknowns.extend(["CPU_IDENTITY_NOT_AUTHENTICATED", "OPAQUE_MEMBERS_NOT_SEMANTICALLY_DECODED",
                         "PROJECT_LANGUAGE_AND_INSTRUCTION_COVERAGE_UNVERIFIED"])
        result = {"engine": ENGINE, "policy": asdict(policy), "profile": PROFILE,
                  "input": {"sha256": _sha(data), "bytes": len(data)}, "format": "CFB_GXW_CANDIDATE",
                  "analysis": {"state": "PARTIAL", "overall_semantic": "UNKNOWN",
                               "official_validation": "NOT_RUN", "production_adoption": "NOT_GRANTED"},
                  "limits": {"os_time_memory_sandbox": False,
                             "registry_tokens": min(MAX_REGISTRY_TOKENS, policy.max_rows)},
                  "cpu": {"state": "PARTIAL" if candidates else "UNKNOWN", "candidates": candidates},
                  "members": inventory, "metadata": metadata}
        if inventory_only:
            result.update(schema=INVENTORY_SCHEMA,
                          pous=[{"name": p["name"], "name_sha256": p["name_sha256"],
                                 "member": p["source_store"], "bytes": p["bytes"],
                                 "sha256": p["source_digest"]} for p in pous],
                          coverage={"scope": "MEMBERS_AND_POU_NAMES_ONLY", "members": len(members),
                                    "pous": len(pous), "decoded_rows": 0,
                                    "reference_scope": "NOT_ANALYZED"},
                          unknowns=sorted(set(unknowns + ["PROGRAM_ROWS_NOT_DECODED", "PARAMETERS_NOT_DECODED",
                                                          "DEVICE_COMMENTS_NOT_DECODED"])))
            return _bounded_result(result, policy)
        ir = reference.project_rows(pous, input_sha256=_sha(data))
        semantic_rows = [{"pou_order": o["pou"]["order"], "record": o["record"],
                          "operands": [{k: v for k, v in operand.items()
                                        if k != "raw_token" or operand["kind"] != "unknown"}
                                       for operand in o["operands"]]}
                         for o in ir["occurrences"]]
        semantic_parameters = []
        # Remove labels, comments, arbitrary tokens and string operands by default.
        if not policy.include_text:
            for occurrence in ir["occurrences"]:
                for operand in occurrence["operands"]:
                    if operand["kind"] in ("literal", "unknown"):
                        operand["raw_token"] = None
                occurrence["comment"]["value"] = None
            for diagnostic in ir["diagnostics"]:
                diagnostic.pop("raw_token", None)
        for occurrence in ir["occurrences"]:
            occurrence["provenance"]["source_locator"] = {
                "member": occurrence["provenance"]["source_store"],
                "pou": occurrence["pou"]["name"], "row": occurrence["record"]["sequence"]}
        params = []
        for entry in metadata:
            if entry["role"] != "parameter" or entry["member"] is None:
                continue
            key = next(k for k, alias in aliases.items() if alias == entry["member"])
            body = members[key]
            try:
                records = parameters.decode_records(body)
                observation = {"member": entry["member"], "state": "FRAMED_ONLY",
                               "records": [{"index": i, "tag": r.tag, "bytes": len(r.payload),
                                            "sha256": _sha(r.payload)} for i, r in enumerate(records)]}
                try:
                    values = parameters.decode_ascii_names(body)
                    semantic_parameters.append({"name_sha256": entry["name_sha256"], "values": values})
                    observation.update(state="OBSERVED_ASCII_NAMES", names=values if policy.include_text else None)
                except ValueError:
                    unknowns.append("PARAM_NAME_ENVELOPE_OR_ENCODING_UNKNOWN")
                params.append(observation)
            except ValueError:
                params.append({"member": entry["member"], "state": "UNKNOWN"})
                unknowns.append("PARAM_FRAMING_UNKNOWN")
        device_comments, device_comment_digest, comment_unknowns = _project_device_comments(
            nested, aliases, metadata, policy)
        unknowns.extend(comment_unknowns)
        result.update(pous=[{"name": p["name"], "member": p["source_store"], "rows": len(p["rows"])} for p in pous],
                      parameters=params, references=ir, text_records=text_records,
                      device_comments=device_comments,
                      supported_observations_sha256=_sha(canonical_json({
                      "pou_names": sorted(found), "rows": semantic_rows,
                      "parameters": semantic_parameters,
                      "text_records": text_digest,
                      "device_comments": device_comment_digest}).encode("ascii")),
                      coverage={"members": len(members), "pous": len(pous), "rows": row_total,
                               "text_records": len(text_records),
                               "device_comment_sources": len(device_comments["sources"]),
                               "device_comments": len(device_comments["records"]),
                               "reference_scope": "OBSERVED_DIRECT_OPERANDS_ONLY"},
                      unknowns=sorted(set(unknowns)))
        return _bounded_result(result, policy)
    except AnalysisError:
        raise
    except Exception:
        raise AnalysisError("DECODE_REJECTED") from None


def analyze_bytes(data, *, policy=Policy()):
    """Inspect fixed bytes without reopening or writing any input."""
    return _analyze(data, policy)


def inventory_bytes(data, *, policy=Policy()):
    """List bounded container/POU observations without decoding rows or parameters."""
    return _analyze(data, policy, inventory_only=True)


def query_bytes(data, device, *, policy=Policy()):
    """Match direct static addresses; unresolved operands remain explicitly listed."""
    target = reference.parse_operand(device, 0) if isinstance(device, str) and len(device) <= 64 else {}
    d = target.get("device")
    if (target.get("status") != "decoded" or not d or d["address"] is None
            or d["index"] or d["indirect"] or d["digit_width"]):
        raise AnalysisError("QUERY_REQUIRES_DIRECT_DEVICE")
    result = _analyze(data, policy)
    matches, unresolved = [], []
    for occurrence in result["references"]["occurrences"]:
        if occurrence["record"]["opcode"].startswith("<"):
            unresolved.append({"locator": occurrence["provenance"]["source_locator"],
                               "reason": "UNKNOWN_INSTRUCTION"})
        for operand in occurrence["operands"]:
            item = {"locator": occurrence["provenance"]["source_locator"], "operand": operand["position"]}
            coverage = operand["coverage"]
            if coverage["state"] in ("UNKNOWN", "DYNAMIC", "LIMIT_REACHED") or operand["status"] != "decoded":
                unresolved.append(item)
            od = operand.get("device")
            if (od and not od["index"] and not od["indirect"] and
                    all(od[k] == d[k] for k in ("family", "module", "word_bit")) and
                    any(a["address"] == d["address"] for a in coverage.get("addresses", []) or [])):
                matches.append(item)
    result["query"] = {"device": device, "matches": matches, "unresolved": unresolved,
                       "state": "PARTIAL", "complete_search": False}
    return _bounded_result(result, policy)


def compare_bytes(left, right, *, policy=Policy()):
    """Separate exact bytes, inventory structure and supported row observations."""
    a, b = _analyze(left, policy), _analyze(right, policy)
    def structure(result):
        return [(m["path_sha256"], m["bytes"]) for m in result["members"]]
    by_path = lambda r: {m["path_sha256"]: m for m in r["members"]}
    am, bm = by_path(a), by_path(b)
    changed = [{"path_sha256": k, "left_member": am.get(k, {}).get("member"),
                "right_member": bm.get(k, {}).get("member")}
               for k in sorted(am.keys() | bm.keys())
               if tuple(am.get(k, {}).get(f) for f in ("bytes", "sha256")) !=
                  tuple(bm.get(k, {}).get(f) for f in ("bytes", "sha256"))]
    return _bounded_result({"engine": ENGINE, "policy": asdict(policy), "profile": PROFILE,
                           "left": a["input"], "right": b["input"],
                           "binary": "SAME" if left == right else "DIFFERENT",
                           "structure": "SAME" if structure(a) == structure(b) else "DIFFERENT",
                           "supported_observations": "SAME" if a["supported_observations_sha256"] == b["supported_observations_sha256"] else "DIFFERENT",
                           "overall_semantic": "UNKNOWN", "changed_members": changed,
                           "coverage": "OBSERVED_ROWS_TEXT_RECORDS_DEVICE_COMMENTS_AND_OPTIONAL_ASCII_NAMES_ONLY",
                           "unknowns": sorted(set(a["unknowns"]+b["unknowns"])),
                           "limits": {"os_time_memory_sandbox": False}}, policy)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inventory", "inspect", "query", "compare", "read-v1", "snapshot"))
    parser.add_argument("path")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--allow-root", required=True)
    parser.add_argument("--right")
    parser.add_argument("--right-sha256")
    parser.add_argument("--device")
    parser.add_argument("--include-text", action="store_true")
    args = parser.parse_args(argv)
    try:
        if (args.operation == "query") != (args.device is not None):
            raise AnalysisError("DEVICE_OPTION_REQUIRES_QUERY")
        if args.operation == "compare":
            if args.right is None or args.right_sha256 is None:
                raise AnalysisError("COMPARE_RIGHT_AND_SHA256_REQUIRED")
        elif args.right is not None or args.right_sha256 is not None:
            raise AnalysisError("RIGHT_OPTIONS_REQUIRE_COMPARE")
        policy = Policy(include_text=args.include_text)
        body = capture_file(args.path, expected_sha256=args.sha256, allow_root=args.allow_root, policy=policy)
        if args.operation == "compare":
            right = capture_file(args.right, expected_sha256=args.right_sha256, allow_root=args.allow_root, policy=policy)
            result = compare_bytes(body, right, policy=policy)
        elif args.operation == "query":
            result = query_bytes(body, args.device, policy=policy)
        elif args.operation == "inventory":
            result = inventory_bytes(body, policy=policy)
        elif args.operation in ("read-v1", "snapshot"):
            import gxw_read_v1
            analysis = analyze_bytes(body, policy=policy)
            literals = {candidate["literal"] for candidate in analysis["cpu"]["candidates"]}
            if not literals or not literals <= {"Q06UDV", "Q06UDVCPU"}:
                raise AnalysisError("PROFILE_LITERAL_MISSING_OR_AMBIGUOUS")
            project = gxw_read_v1.build_projection if args.operation == "read-v1" else gxw_read_v1.device_snapshot
            try:
                result = _bounded_result(project(analysis, include_text=args.include_text), policy)
            except gxw_read_v1.ReadV1Error as error:
                raise AnalysisError(str(error)) from None
        else:
            result = analyze_bytes(body, policy=policy)
        print(canonical_json(result))
        return 0
    except AnalysisError as error:
        print(canonical_json({"engine_schema": SCHEMA, "state": "REJECTED", "reason": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
