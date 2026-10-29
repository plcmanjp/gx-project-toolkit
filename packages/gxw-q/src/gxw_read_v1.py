"""Pure, conservative Read-V1 views over an existing project analysis.

The finite form list is an observation contract, not instruction validation or
native acceptance. Access and address spans come from Reference IR, never from
this contract. No project bytes, files, engine state, or runtime are consulted.
"""
from __future__ import annotations

from copy import deepcopy
import json
import math
import re

import gxw_reference_ir as reference

PROFILE = "q06udv-simple-ladder-read-v1"
_BIT = ("B", "C", "F", "L", "M", "SB", "SM", "ST", "T", "X", "Y")
_WORD = ("D", "FD", "R", "SD", "SW", "W", "Z", "ZR")
_FAMILIES = frozenset((*_BIT, *_WORD, "DY", "G"))
_FORMS = {"END": (), **{op: ("direct_bit",) for op in
          ("LD", "LDI", "AND", "ANI", "OR", "ORI", "OUT", "SET", "RST")},
          "MOV": ("direct_word_or_kh16", "direct_word"),
          "DMOV": ("direct_word_or_kh32", "direct_word")}
_ACCESS = {"read", "write", "both", "unknown"}
_COVERAGE = {"STATIC", "DYNAMIC", "UNKNOWN", "LIMIT_REACHED", "NOT_APPLICABLE"}
_ROLES = {"pou_resource", "pou_program", "parameter", "opaque"}


class ReadV1Error(ValueError):
    """Stable, privacy-safe rejection of malformed analysis data."""


def _require(condition, reason):
    if not condition:
        raise ReadV1Error(reason)


def _obj(value):
    _require(type(value) is dict, "INVALID_OBJECT")
    return value


def _list(value):
    _require(type(value) is list, "INVALID_LIST")
    return value


def _text(value, *, nullable=False):
    _require((nullable and value is None) or type(value) is str, "INVALID_TEXT")
    return value


def _integer(value, *, nullable=False):
    _require((nullable and value is None) or (type(value) is int and value >= 0),
             "INVALID_NONNEGATIVE_INTEGER")
    return value


def _digest(value, *, nullable=False):
    _require((nullable and value is None) or
             (type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None),
             "INVALID_SHA256")
    return value


def _member(value):
    _require(type(value) is str and re.fullmatch(r"m[0-9]{4,}", value) is not None,
             "INVALID_MEMBER_ID")
    return value


def _code(value):
    _require(type(value) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", value) is not None,
             "INVALID_REASON_CODE")
    return value


def _choice(value, choices):
    _require(type(value) is str and value in choices, "INVALID_ENUM_VALUE")
    return value


def _opcode(value, include_text):
    _text(value)
    if value.startswith("<"):
        return value if include_text else None
    _require(re.fullmatch(r"[A-Z0-9.$+*/<>=!-]{1,64}", value) is not None, "INVALID_OPCODE")
    return value


def _sorted(items):
    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True))


def promise_manifest() -> dict:
    """Return an independent copy of the finite candidate observation contract."""
    return {
        "profile": PROFILE, "evidence_status": "OBSERVATION_CONTRACT",
        "completion": "NOT_ESTABLISHED",
        "forms": [{"form_id": op.lower() + "_" + str(len(forms)), "opcode": op,
                   "arity": len(forms), "operands": list(forms),
                   "evidence_status": "OBSERVATION_CONTRACT", "completion": "NOT_ESTABLISHED"}
                  for op, forms in sorted(_FORMS.items())],
        "direct_device_forms": {"bit_families": list(_BIT), "word_families": list(_WORD),
                                "excluded_modifiers": ["digit_width", "index", "indirect",
                                                       "module", "word_bit"]},
        "constants": {op: {"K": {"min": -(1 << (width - 1)), "max": (1 << (width - 1)) - 1},
                           "H": {"min": 0, "max": (1 << width) - 1}}
                      for op, width in (("MOV", 16), ("DMOV", 32))},
    }


def _index(value):
    if value is None:
        return None
    item = _obj(value)
    _choice(item.get("kind"), {"Z", "ZZ"})
    _require(item.get("access") == "read", "INVALID_INDEX")
    return {"kind": item["kind"], "number": _integer(item.get("number")), "access": "read"}


def _device(value):
    if value is None:
        return None
    d = _obj(value)
    family = _choice(d.get("family"), _FAMILIES)
    radix = d.get("display_radix")
    _require(type(radix) is int and radix == (16 if family in reference.HEX_FAMILIES else 10),
             "INVALID_DEVICE_RADIX")
    _require(type(d.get("indirect")) is bool, "INVALID_DEVICE")
    _choice(d.get("unit"), {"bit", "word"})
    digit = _integer(d.get("digit_width"), nullable=True)
    _require(digit is None or 1 <= digit <= 8, "INVALID_DIGIT_WIDTH")
    expected_unit = "bit" if family in reference.BIT_FAMILIES and d.get("word_bit") is None else "word"
    _require(d["unit"] == expected_unit, "INVALID_DEVICE_UNIT")
    return {"family": family, "address": _integer(d.get("address"), nullable=True),
            "display_radix": radix, "module": _integer(d.get("module"), nullable=True),
            "word_bit": _integer(d.get("word_bit"), nullable=True), "index": _index(d.get("index")),
            "indirect": d["indirect"], "digit_width": digit, "unit": d["unit"]}


def _constant(value):
    if value is None:
        return None
    c = _obj(value)
    _choice(c.get("notation"), {"K", "H", "E"})
    number = c.get("value")
    _require(number is None or type(number) is int or
             (type(number) is float and math.isfinite(number)), "INVALID_CONSTANT_VALUE")
    _require(c["notation"] == "E" or number is None or type(number) is int, "INVALID_CONSTANT_VALUE")
    return {"notation": c["notation"], "value": number, "index": _index(c.get("index"))}


def _coverage(value):
    c = _obj(value)
    _choice(c.get("state"), _COVERAGE)
    addresses = c.get("addresses")
    if addresses is not None:
        addresses = _list(addresses)
        cleaned = []
        for a in addresses:
            a = _obj(a)
            _choice(a.get("family"), _FAMILIES)
            cleaned.append({"family": a["family"], "address": _integer(a.get("address")),
                            "module": _integer(a.get("module"), nullable=True),
                            "word_bit": _integer(a.get("word_bit"), nullable=True),
                            "offset": _integer(a.get("offset"))})
        addresses = _sorted(cleaned)
    return {"state": c["state"], "word_width": _integer(c.get("word_width"), nullable=True),
            "addresses": addresses, "reason": _code(c.get("reason"))}


def _operand(value, position, include_text):
    o = _obj(value)
    _require(type(o.get("position")) is int and o["position"] == position, "INVALID_OPERAND_POSITION")
    _choice(o.get("kind"), {"device", "constant", "literal", "control", "unknown"})
    _choice(o.get("status"), {"decoded", "unknown"})
    _choice(o.get("access"), _ACCESS)
    raw = _text(o.get("raw_token"), nullable=True)
    device, constant = _device(o.get("device")), _constant(o.get("constant"))
    _require((o["kind"] == "device") == (device is not None) and
             (o["kind"] == "constant") == (constant is not None), "INVALID_OPERAND_BINDING")
    if o["status"] == "decoded":
        _require(device is None or device["address"] is not None, "INVALID_DECODED_DEVICE")
        _require(constant is None or constant["value"] is not None, "INVALID_DECODED_CONSTANT")
    if raw is not None and o["kind"] in {"device", "constant"}:
        parsed = reference.parse_operand(raw, position)
        _require(parsed["kind"] == o["kind"] and parsed["status"] == o["status"] and
                 _device(parsed["device"]) == device and _constant(parsed["constant"]) == constant,
                 "OPERAND_TOKEN_MISMATCH")
    coverage = _coverage(o.get("coverage"))
    _require(not coverage["addresses"] or device is not None, "INVALID_COVERAGE_BINDING")
    if coverage["addresses"]:
        seen = set()
        for a in coverage["addresses"]:
            key = (a["family"], a["address"], a["module"], a["word_bit"], a["offset"])
            _require(key not in seen and device["address"] is not None and
                     all(a[k] == device[k] for k in ("family", "module", "word_bit")) and
                     a["address"] == device["address"] + a["offset"], "INVALID_COVERAGE_BINDING")
            seen.add(key)
    return {"position": position, "kind": o["kind"], "status": o["status"],
            "raw_token": raw if include_text else None, "access": o["access"],
            "access_basis": _code(o.get("access_basis")), "device": device,
            "constant": constant, "coverage": coverage}


def _contract(opcode, operands, raw_operands):
    forms = _FORMS.get(opcode)
    if forms is None:
        return None, "OPCODE_OUTSIDE_V1"
    if len(operands) != len(forms):
        return None, "ARITY_OUTSIDE_V1"
    for form, o, raw in zip(forms, operands, raw_operands):
        d, c = o["device"], o["constant"]
        direct = (o["status"] == "decoded" and d is not None and d["address"] is not None and
                  all(d[k] is None for k in ("module", "word_bit", "index", "digit_width")) and
                  not d["indirect"])
        if direct and d["family"] in (_BIT if form == "direct_bit" else _WORD):
            continue
        if form.startswith("direct_word_or_kh") and c is not None and o["status"] == "decoded":
            width = 16 if form.endswith("16") else 32
            token = raw.get("raw_token")
            if (c["index"] is None and type(c["value"]) is int and type(token) is str and
                    ((c["notation"] == "K" and re.fullmatch(r"K-?[0-9]+", token) and
                      -(1 << (width - 1)) <= c["value"] < (1 << (width - 1))) or
                     (c["notation"] == "H" and re.fullmatch(r"H[0-9A-F]+", token) and
                      0 <= c["value"] < (1 << width)))):
                continue
        return None, "OPERAND_FORM_OUTSIDE_V1"
    return opcode.lower() + "_" + str(len(forms)), None


def build_projection(analysis: dict, *, include_text: bool = False) -> dict:
    """Project only allowlisted observations; preserve absence and unknowns."""
    a = _obj(analysis)
    _require(type(include_text) is bool, "INVALID_INCLUDE_TEXT")
    sha = _digest(_obj(a.get("input")).get("sha256"))
    members = [_member(_obj(m).get("member")) for m in _list(a.get("members"))]
    _require(len(members) == len(set(members)), "DUPLICATE_MEMBER")
    known_members = set(members)
    metadata = []
    for m in _list(a.get("metadata")):
        m = _obj(m)
        ident = _text(m.get("id"))
        _require(re.fullmatch(r"0|[1-9][0-9]{0,9}", ident) is not None, "INVALID_METADATA_ID")
        member = m.get("member")
        _require(member is None or _member(member) in known_members, "UNKNOWN_METADATA_MEMBER")
        _choice(m.get("role"), _ROLES)
        _choice(m.get("state"), {"MAPPED", "UNRESOLVED"})
        _require((m["state"] == "MAPPED") == (member is not None), "INVALID_METADATA_BINDING")
        metadata.append({"id": ident, "member": member, "role": m["role"], "state": m["state"]})
    _require(len({m["id"] for m in metadata}) == len(metadata), "DUPLICATE_METADATA_ID")
    psource = [_obj(p) for p in _list(a.get("pous"))]
    _require(all(_member(p.get("member")) in known_members for p in psource), "UNKNOWN_POU_MEMBER")
    _require(len({p["member"] for p in psource}) == len(psource), "DUPLICATE_POU_MEMBER")
    psource.sort(key=lambda p: p["member"])
    by_member, pous, edges = {}, [], []

    def edge(reason, *, member=None, pou=None, locator=None, operand_position=None):
        edges.append({"reason": reason, "member": member, "pou": pou,
                      "locator": locator, "operand_position": operand_position})

    ir = a.get("references")
    observed = ir is not None and a.get("schema") != "plcman.gxw.project-inventory/1"
    if not psource:
        edge("NO_RECOGNIZED_POU")
    for i, p in enumerate(psource):
        name = _text(p.get("name"))
        member, alias = p["member"], f"p{i:04d}"
        roles = _sorted([{k: m[k] for k in ("id", "role", "state")}
                         for m in metadata if m["member"] == member])
        basic = {m["role"] for m in roles if m["state"] == "MAPPED" and
                 m["role"] in {"pou_resource", "pou_program"}}
        rows = _integer(p.get("rows")) if observed and "rows" in p else None
        item = {"pou": alias, "member": member, "name": name if include_text else None,
                "role": next(iter(basic)) if len(basic) == 1 else "UNVERIFIED",
                "metadata_roles": roles,
                "rows": {"state": "OBSERVED" if observed and rows is not None else "NOT_ANALYZED",
                         "observed_count": rows, "reference_occurrences": 0 if observed else None}}
        by_member[member] = (name, item)
        pous.append(item)
        if item["role"] == "UNVERIFIED":
            edge("POU_ROLE_UNVERIFIED", member=member, pou=alias)
        if rows is None:
            edge("PROGRAM_ROWS_NOT_ANALYZED", member=member, pou=alias)
    for reason in _list(a.get("unknowns", [])):
        edge(_code(reason))
    for m in metadata:
        if m["state"] == "UNRESOLVED":
            edge("METADATA_TARGET_UNRESOLVED", member=m["member"])

    def binding(member, name):
        _require(member in by_member and _text(name) == by_member[member][0], "INVALID_POU_BINDING")
        return by_member[member][1]["pou"]

    def locator(member, name, sequence, source=None):
        alias = binding(member, name)
        if source is not None:
            if type(source) is dict:
                _require(source.get("member") == member and source.get("pou") == name and
                         type(source.get("row")) is int and source["row"] == sequence,
                         "INVALID_SOURCE_LOCATOR")
            else:
                _require(source == f"_hdb/{member}:row:{sequence}", "INVALID_SOURCE_LOCATOR")
        return {"member": member, "pou": alias, "row": sequence}

    comments = {"device_comment_sources": [], "device_comment_records": [],
                "reference_ir_comments": [], "text_records": []}
    instructions, unsupported, unknown = [], [], []
    semantic_members = set()
    reported = None
    if observed:
        ir = _obj(ir)
        _require(ir.get("schema_name") == reference.SCHEMA_NAME and
                 type(ir.get("schema_version")) is int and ir["schema_version"] == reference.SCHEMA_VERSION,
                 "INVALID_REFERENCE_SCHEMA")
        _require(_digest(_obj(ir.get("input")).get("sha256")) == sha, "REFERENCE_SOURCE_MISMATCH")
        ir_state = _obj(ir.get("analysis")).get("state")
        _choice(ir_state, {"PARTIAL", "COMPLETE"})
        if ir_state == "PARTIAL":
            edge("REFERENCE_IR_PARTIAL")
        occurrences = _list(ir.get("occurrences"))
        coverage = _obj(ir.get("coverage"))
        reported = _integer(coverage.get("unknown_instructions"))
        if _integer(coverage.get("occurrences")) != len(occurrences):
            edge("REFERENCE_OCCURRENCE_COUNT_MISMATCH")
        seen, operand_total = set(), 0
        for occurrence in occurrences:
            occurrence = _obj(occurrence)
            provenance, record, p = (_obj(occurrence.get(k)) for k in ("provenance", "record", "pou"))
            member = _member(provenance.get("source_store"))
            sequence = _integer(record.get("sequence"))
            _require(provenance.get("source_locator") is not None, "SOURCE_LOCATOR_REQUIRED")
            loc = locator(member, p.get("name"), sequence, provenance.get("source_locator"))
            _require((member, sequence) not in seen, "DUPLICATE_REFERENCE_LOCATOR")
            seen.add((member, sequence))
            op = _text(record.get("opcode"))
            safe_op = _opcode(op, include_text)
            raw_operands = _list(occurrence.get("operands"))
            operands = [_operand(o, i, include_text) for i, o in enumerate(raw_operands)]
            operand_total += len(operands)
            alias = loc["pou"]
            item = {"pou": alias, "member": member, "locator": loc, "opcode": safe_op,
                    "state": "UNKNOWN" if op.startswith("<") else "UNSUPPORTED_IN_V1",
                    "form_id": None, "evidence_status": "NOT_ESTABLISHED", "operands": operands}
            if op.startswith("<"):
                unknown.append({k: item[k] for k in ("pou", "member", "locator", "opcode")})
                edge("UNKNOWN_INSTRUCTION", member=member, pou=alias, locator=loc)
            else:
                form, reason = _contract(op, operands, raw_operands)
                if form is not None:
                    item.update(state="OBSERVATION_CONTRACT", form_id=form)
                else:
                    unsupported.append({**{k: item[k] for k in ("pou", "member", "locator", "opcode")},
                                        "reason": reason})
                    edge("UNSUPPORTED_IN_V1", member=member, pou=alias, locator=loc)
            for o in operands:
                reasons = []
                if o["status"] != "decoded":
                    reasons.append("OPERAND_UNDECODED")
                if o["access"] == "unknown":
                    reasons.append("REFERENCE_ACCESS_UNKNOWN")
                c = o["coverage"]
                if c["state"] in {"DYNAMIC", "UNKNOWN", "LIMIT_REACHED"}:
                    reasons.append(c["reason"])
                if o["device"] and c["state"] == "STATIC" and not c["addresses"]:
                    reasons.append("STATIC_COVERAGE_EMPTY")
                for reason in reasons:
                    edge(reason, member=member, pou=alias, locator=loc, operand_position=o["position"])
            comment = _obj(occurrence.get("comment"))
            state = _code(comment.get("state"))
            value = _text(comment.get("value"), nullable=True)
            if state != "UNAVAILABLE":
                comments["reference_ir_comments"].append({"pou": alias, "member": member,
                    "locator": loc, "state": state, "text": value if include_text else None,
                    "ownership": "UNVERIFIED", "owner": None})
            by_member[member][1]["rows"]["reference_occurrences"] += 1
            if not op.startswith("<"):
                semantic_members.add(member)
            instructions.append(item)
        if _integer(coverage.get("operands")) != operand_total:
            edge("REFERENCE_OPERAND_COUNT_MISMATCH")
        if reported != len(unknown):
            edge("UNKNOWN_INSTRUCTION_COUNT_MISMATCH")
        for d in _list(ir.get("diagnostics", [])):
            d = _obj(d)
            member = _member(d.get("source_store"))
            alias = binding(member, d.get("pou"))
            diagnostic_loc = (locator(member, d["pou"], _integer(d["row"]), d.get("source_locator"))
                              if "row" in d else None)
            edge(_code(d["reason"]) if d.get("reason") is not None else "REFERENCE_IR_DIAGNOSTIC",
                 member=member, pou=alias, locator=diagnostic_loc)
    else:
        edge("REFERENCES_NOT_ANALYZED")

    for t in _list(a.get("text_records", [])):
        t = _obj(t)
        member, sequence = _member(t.get("member")), _integer(t.get("sequence"))
        alias = binding(member, t.get("pou"))
        _choice(t.get("kind"), {"statement", "note"})
        attachment = t.get("attachment")
        if attachment is not None:
            _require(t["kind"] == "note", "INVALID_STATEMENT_ATTACHMENT")
            attachment = _obj(attachment)
            attachment = {"sequence": _integer(attachment.get("sequence")),
                          "opcode": _opcode(attachment.get("opcode"), include_text)}
        raw_type = _text(t.get("raw_type"), nullable=True)
        _require(raw_type is None or re.fullmatch(r"0x[0-9a-fA-F]{2}", raw_type) is not None,
                 "INVALID_TEXT_RAW_TYPE")
        _require(t.get("subtype") is None or
                 (type(t["subtype"]) is str and t["subtype"] in {"s", "i"}), "INVALID_TEXT_SUBTYPE")
        text = _text(t.get("text"), nullable=True)
        text_state = _code(t.get("state"))
        comments["text_records"].append({"pou": alias, "member": member, "sequence": sequence,
            "kind": t["kind"], "state": text_state,
            "text": text if include_text else None,
            "text_sha256": _digest(t.get("text_sha256"), nullable=True),
            "hash_basis": _code(t["hash_basis"]) if t.get("hash_basis") is not None else None,
            "raw_type": raw_type, "subtype": None if t["kind"] == "note" else t.get("subtype"),
            "source_step_width": _integer(t.get("source_step_width"), nullable=True),
            "attachment": attachment, "ownership": "UNVERIFIED", "owner": None})
        if text_state == "OBSERVED_SOURCE":
            semantic_members.add(member)
        else:
            edge("TEXT_RECORD_UNRESOLVED", member=member, pou=alias)
        edge("TEXT_OWNERSHIP_UNVERIFIED", member=member, pou=alias)
        if t["kind"] == "note":
            edge("NOTE_SUBTYPE_UNVERIFIED", member=member, pou=alias)
            if not attachment or not any(i["member"] == member and i["locator"]["row"] == attachment["sequence"]
                                         and i["opcode"] is not None and i["opcode"] == attachment["opcode"]
                                         for i in instructions):
                edge("NOTE_ATTACHMENT_UNRESOLVED", member=member, pou=alias)
    for p in pous:
        rows = p["rows"]["observed_count"]
        row_ids = [i["locator"]["row"] for i in instructions if i["member"] == p["member"]]
        row_ids += [t["sequence"] for t in comments["text_records"] if t["member"] == p["member"]]
        if rows is not None and (len(row_ids) != len(set(row_ids)) or len(row_ids) != rows or
                                 (row_ids and max(row_ids) >= rows)):
            edge("POU_ROW_COUNT_MISMATCH", member=p["member"], pou=p["pou"])
    dc = _obj(a.get("device_comments", {"sources": [], "records": []}))
    for s in _list(dc.get("sources")):
        s = _obj(s)
        member = _member(s.get("member"))
        _require(member in known_members, "UNKNOWN_COMMENT_MEMBER")
        source_state = _code(s.get("state"))
        source_encoding = s.get("encoding")
        _require(source_encoding is None or
                 (type(source_encoding) is str and source_encoding in {"utf-16le", "cp1252", "cp949"}),
                 "INVALID_COMMENT_ENCODING")
        comments["device_comment_sources"].append({
            "member": member, "state": source_state,
            "record_count": _integer(s.get("record_count"), nullable=True),
            "reason": _code(s["reason"]) if s.get("reason") is not None else None,
            "encoding": source_encoding, "encoding_state": "UNVERIFIED",
            "ownership": "UNVERIFIED", "owner": None})
        if source_state != "OBSERVED_SOURCE":
            edge("DEVICE_COMMENT_SOURCE_UNRESOLVED", member=member)
    for c in _list(dc.get("records")):
        c = _obj(c)
        member = _member(c.get("member"))
        _require(member in known_members, "UNKNOWN_COMMENT_MEMBER")
        token = _text(c.get("device"))
        parsed = reference.parse_operand(token, 0)
        device = _device(parsed["device"])
        encoding = c.get("encoding")
        _require(encoding is None or (type(encoding) is str and encoding in {"utf-16le", "cp1252", "cp949"}),
                 "INVALID_COMMENT_ENCODING")
        direct = (device and parsed["status"] == "decoded" and not device["indirect"] and
                  all(device[k] is None for k in ("index", "digit_width")))
        text = _text(c.get("text"), nullable=True)
        comments["device_comment_records"].append({"member": member,
            "sequence": _integer(c.get("sequence")),
            "device": _device_label(device) if direct else None,
            "state": _code(c.get("state")),
            "text": text if include_text else None,
            "text_sha256": _digest(c.get("text_sha256"), nullable=True), "encoding": c.get("encoding"),
            "ownership": "UNVERIFIED", "owner": None})
        if c["state"] == "OBSERVED_SOURCE":
            semantic_members.add(member)
        edge("DEVICE_COMMENT_OWNERSHIP_UNVERIFIED", member=member)
        if not direct:
            edge("COMMENT_DEVICE_UNRESOLVED", member=member)
    for p in _list(a.get("parameters", [])):
        p = _obj(p)
        member = _member(p.get("member"))
        _require(member in known_members, "UNKNOWN_PARAMETER_MEMBER")
        if _code(p.get("state")) == "OBSERVED_ASCII_NAMES":
            semantic_members.add(member)
    return {"schema": "gx-project-toolkit.read-v1/1", "profile": PROFILE, "source_sha256": sha,
            "state": "PARTIAL", "complete_search": False,
            "reference_state": "OBSERVED" if observed else "NOT_ANALYZED",
            "promise_manifest": promise_manifest(), "pous": pous,
            "instructions": sorted(instructions, key=lambda i: (i["member"], i["locator"]["row"])),
            "unsupported_in_v1": _sorted(unsupported),
            "unknown_instructions": {"state": "OBSERVED" if observed else "NOT_ANALYZED",
                                     "count": len(unknown) if observed else None,
                                     "reported_count": reported, "occurrences": _sorted(unknown)},
            "unrecognized_members": [{"member": m, "reason": "NO_SEMANTIC_DECODER_OBSERVATION"}
                                     for m in sorted(known_members - semantic_members)],
            "unresolved_edges": _sorted(edges),
            "comments": {k: _sorted(v) for k, v in comments.items()}}


def _device_label(d):
    if d["address"] is None:
        return None
    address = format(d["address"], "X") if d["display_radix"] == 16 else str(d["address"])
    prefix = "" if d.get("module") is None else f"U{d['module']:X}\\"
    suffix = "" if d.get("word_bit") is None else f".{d['word_bit']:X}"
    return prefix + d["family"] + address + suffix


def device_snapshot(analysis: dict, *, include_text: bool = False) -> dict:
    """Deterministic observed address references, always explicitly partial."""
    projection = build_projection(analysis, include_text=include_text)
    devices = {}
    for instruction in projection["instructions"]:
        for operand in instruction["operands"]:
            d, coverage = operand["device"], operand["coverage"]
            if d is None or d["address"] is None:
                continue
            resolved = coverage["state"] == "STATIC" and bool(coverage["addresses"])
            addresses = coverage["addresses"] if resolved else [{**d, "offset": None}]
            for address in addresses:
                radix = 16 if address["family"] in reference.HEX_FAMILIES else 10
                key = (address["family"], address["address"], radix,
                       -1 if address["module"] is None else address["module"],
                       -1 if address["word_bit"] is None else address["word_bit"])
                if key not in devices:
                    info = {k: address[k] for k in ("family", "address", "module", "word_bit")}
                    info["display_radix"] = radix
                    devices[key] = {"device": _device_label(info), **info, "references": [],
                                    "comments": {k: [] for k in projection["comments"]}}
                devices[key]["references"].append({
                    **{k: instruction[k] for k in ("pou", "member", "locator", "opcode")},
                    "operand_position": operand["position"], "access": operand["access"],
                    "access_basis": operand["access_basis"], "coverage_state": coverage["state"],
                    "coverage_relation": "COVERED_ADDRESS" if resolved else "BASE_ONLY",
                    "covered_offset": address["offset"], "instruction_state": instruction["state"]})
    comment_index, row_index, note_index = {}, {}, {}
    for c in projection["comments"]["device_comment_records"]:
        comment_index.setdefault(c["device"], []).append(c)
    for c in projection["comments"]["reference_ir_comments"]:
        loc = c["locator"]
        row_index.setdefault((c["member"], c["pou"], loc["row"]), []).append(c)
    for c in projection["comments"]["text_records"]:
        attachment = c["attachment"]
        if attachment and attachment["opcode"] is not None:
            note_index.setdefault((c["member"], c["pou"], attachment["sequence"], attachment["opcode"]), []).append(c)
    for device in devices.values():
        refs = device["references"]
        device["references"] = sorted(refs, key=lambda r: (r["member"], r["locator"]["row"],
                                                          r["operand_position"],
                                                          -1 if r["covered_offset"] is None else r["covered_offset"]))
        device["comments"]["device_comment_records"] = deepcopy(comment_index.get(device["device"], []))
        source_members = {c["member"] for c in device["comments"]["device_comment_records"]}
        device["comments"]["device_comment_sources"] = [
            deepcopy(s) for s in projection["comments"]["device_comment_sources"] if s["member"] in source_members]
        row_keys = {(r["member"], r["pou"], r["locator"]["row"]) for r in refs}
        note_keys = {(r["member"], r["pou"], r["locator"]["row"], r["opcode"]) for r in refs}
        device["comments"]["reference_ir_comments"] = _sorted(
            [deepcopy(c) for key in row_keys for c in row_index.get(key, [])])
        device["comments"]["text_records"] = _sorted(
            [deepcopy(c) for key in note_keys for c in note_index.get(key, [])])
    return {"schema": "gx-project-toolkit.device-references/1", "profile": PROFILE,
            "source_sha256": projection["source_sha256"], "state": "PARTIAL", "complete_search": False,
            **{k: projection[k] for k in ("reference_state", "unknown_instructions", "unresolved_edges")},
            "devices": [devices[k] for k in sorted(devices)], "comments": projection["comments"]}
