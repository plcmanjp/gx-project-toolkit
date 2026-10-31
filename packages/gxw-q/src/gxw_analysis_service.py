"""Registered read service with operator-owned disclosure (Windows 11).

The local operator owns configuration and disclosure. Tool callers supply IDs,
never paths, digests, policy overrides, source text or worker commands.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import sysconfig
import time
import uuid

import gxw_project_analysis as engine

SCHEMA = "plcman.gxw.readonly-service/1"
CONFIG_SCHEMA = "plcman.gxw.readonly-config/1"
PROFILE = "q06udv-simple-ladder-observed"
OPERATIONS = ("inventory", "inspect", "query", "compare")
ID = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")
HEX = re.compile(r"[0-9a-f]{64}\Z")
RESPONSE_LIMIT = 64 * 1024
CLEANUP_TIMEOUT = 1.0
DETAIL_FIELDS = frozenset({"pou_names", "device_comments", "text_records", "references"})
DISCLOSURES = frozenset({"summary-only", "authorized-detail"})
REASON = re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z")


class ServiceError(ValueError):
    """Only controlled reason codes cross the protocol boundary."""

    def __init__(self, reason):
        super().__init__(reason if type(reason) is str and REASON.fullmatch(reason) else "REQUEST_REJECTED")


def reject(reason):
    raise ServiceError(reason)


def exact_keys(value, required, optional=()):
    if (type(value) is not dict or not set(required) <= value.keys()
            or value.keys() - set(required) - set(optional)):
        reject("INVALID_CONFIG")


def alias(key, value):
    return "a-" + hmac.new(bytes.fromhex(key), str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def directory_identity(path):
    engine._path_chain(path)
    return [(str(p), p.stat().st_dev, p.stat().st_ino) for p in (path, *path.parents)]


def _worker_launch(fixedworker, optimize=False):
    """Launch the actual CPython PID; defer the trusted runtime site until gate admission."""
    try:
        raw_base = getattr(sys, "_base_executable", None)
        if type(raw_base) is not str or not Path(raw_base).is_absolute():
            raise ValueError
        base = Path(raw_base).resolve(strict=True)
        base_root, prefix = Path(sys.base_prefix).resolve(strict=True), Path(sys.prefix).resolve(strict=True)
        if (not base.is_file() or base.name.lower() != "python.exe" or base.parent != base_root or
                (prefix != base_root and base == Path(sys.executable).resolve(strict=True))):
            raise ValueError
        raw_site = sysconfig.get_path("purelib")
        if type(raw_site) is not str or not Path(raw_site).is_absolute():
            raise ValueError
        runtime_site = Path(raw_site).resolve(strict=True)
        if not runtime_site.is_dir() or runtime_site != (prefix / "Lib/site-packages").resolve(strict=True):
            raise ValueError
        if type(fixedworker) is not type(Path()) or not fixedworker.is_absolute():
            raise ValueError
        worker = fixedworker.resolve(strict=True)
        source = Path(__file__).resolve().parent
        if (worker.parent != source or not worker.is_file() or worker.name not in
                {"gxw_analysis_worker.py", "gxw_pou_private_worker.py"}):
            raise ValueError
        if type(optimize) not in (bool, int) or optimize not in (0, 1, 2):
            raise ValueError
        command = [str(base), "-I", "-S", "-B"]
        if optimize:
            command.append("-O" if optimize == 1 else "-OO")
        command.append(str(worker))
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() not in {"GXW_TOOLKIT_WORKER_SITE", "__PYVENV_LAUNCHER__"}}
        environment["GXW_TOOLKIT_WORKER_SITE"] = str(runtime_site)
        return command, environment
    except Exception:
        raise ServiceError("RESOURCE_ISOLATION_UNAVAILABLE") from None


def detail_fields(disclosure, project):
    """Recheck mutable registry entries before dispatch and inside the child."""
    if type(disclosure) is not str or disclosure not in DISCLOSURES:
        reject("DISCLOSURE_OR_SCHEMA_REJECTED")
    if (project.get("profile") != PROFILE or project.get("authority") != "authorized-synthetic"
            or type(project.get("sha256")) is not str or HEX.fullmatch(project["sha256"]) is None):
        reject("PROFILE_OR_AUTHORITY_REJECTED")
    if disclosure == "summary-only":
        if "detail_fields" in project:
            reject("DETAIL_GRANT_REJECTED")
        return ()
    fields = project.get("detail_fields")
    if fields is None:
        reject("DETAIL_GRANT_REQUIRED")
    if (type(fields) is not list or not 1 <= len(fields) <= len(DETAIL_FIELDS)
            or any(type(field) is not str or field not in DETAIL_FIELDS for field in fields)
            or len(fields) != len(set(fields))):
        reject("DETAIL_GRANT_REJECTED")
    return tuple(sorted(fields))


def grant_identifier(key, ident, project, fields):
    return alias(key, engine.canonical_json({"project": ident, "source": project["sha256"], "fields": list(fields)}))


@dataclass(frozen=True)
class Registry:
    projects: dict
    alias_key: str
    audit_root: Path
    timeout: float = 10.0
    memory_bytes: int = 256 * 1024 * 1024
    page_size: int = 100
    config_sha256: str = ""
    disclosure: str = "summary-only"

    @classmethod
    def load(cls, path, digest):
        try:
            path = engine._safe_path(path)
            body = engine.capture_file(path, expected_sha256=digest, allow_root=path.parent,
                                       policy=engine.Policy(max_input_bytes=65536))
            def pairs(items):
                result = {}
                for k, v in items:
                    if k in result:
                        reject("DUPLICATE_CONFIG_KEY")
                    result[k] = v
                return result
            config = json.loads(body, object_pairs_hook=pairs)
            exact_keys(config, ("schema", "disclosure", "alias_key", "audit_root", "projects"), ("limits",))
            if config["schema"] != CONFIG_SCHEMA or type(config["disclosure"]) is not str or config["disclosure"] not in DISCLOSURES:
                reject("DISCLOSURE_OR_SCHEMA_REJECTED")
            if type(config["alias_key"]) is not str or not HEX.fullmatch(config["alias_key"]):
                reject("INVALID_ALIAS_KEY")
            projects = config["projects"]
            if type(projects) is not dict or not 1 <= len(projects) <= 32:
                reject("INVALID_REGISTRY")
            for ident, project in projects.items():
                if not ID.fullmatch(ident):
                    reject("INVALID_PROJECT_ID")
                exact_keys(project, ("path", "root", "sha256", "profile", "authority"), ("detail_fields",))
                detail_fields(config["disclosure"], project)
                if (project["profile"] != PROFILE or project["authority"] != "authorized-synthetic"
                        or type(project["sha256"]) is not str or not HEX.fullmatch(project["sha256"])):
                    reject("PROFILE_OR_AUTHORITY_REJECTED")
                for field in ("path", "root"):
                    if type(project[field]) is not str or not Path(project[field]).is_absolute():
                        reject("ABSOLUTE_REGISTRATION_REQUIRED")
                    project[field] = str(engine._safe_path(project[field]))
                source, root = Path(project["path"]), Path(project["root"])
                if source == root or not source.is_relative_to(root) or not root.is_dir():
                    reject("PATH_OUTSIDE_ALLOW_ROOT")
                engine._path_chain(root)
            raw_root = config["audit_root"]
            if type(raw_root) is not str or not Path(raw_root).is_absolute():
                reject("INVALID_AUDIT_ROOT")
            audit = engine._safe_path(raw_root)
            if not audit.is_dir():
                reject("INVALID_AUDIT_ROOT")
            engine._path_chain(audit)
            for project in projects.values():
                root = Path(project["root"])
                if audit.is_relative_to(root) or root.is_relative_to(audit):
                    reject("AUDIT_SOURCE_OVERLAP")
            limits = config.get("limits", {})
            exact_keys(limits, (), ("timeout_seconds", "memory_bytes", "page_size"))
            timeout = limits.get("timeout_seconds", 10.0)
            memory = limits.get("memory_bytes", 256 * 1024 * 1024)
            page = limits.get("page_size", 100)
            if type(timeout) not in (int, float) or not 0.1 <= timeout <= 60:
                reject("INVALID_TIME_LIMIT")
            if type(memory) is not int or not 32 * 1024 * 1024 <= memory <= 1024 ** 3:
                reject("INVALID_MEMORY_LIMIT")
            if type(page) is not int or not 1 <= page <= 200:
                reject("INVALID_PAGE_LIMIT")
            return cls(projects, config["alias_key"], audit, timeout, memory, page,
                       hashlib.sha256(body).hexdigest(), config["disclosure"])
        except ServiceError:
            raise
        except engine.AnalysisError as exc:
            raise ServiceError(str(exc)) from None
        except Exception:
            raise ServiceError("CONFIG_REJECTED") from None


class WorkerJob:
    """A job controls only the analysis child and its descendants, never GX."""

    def __init__(self, pid, memory):
        if sys.platform != "win32":
            reject("RESOURCE_ISOLATION_UNAVAILABLE")
        import win32api
        import win32job
        self.job = None
        try:
            self.job = win32job.CreateJobObject(None, "")
            info = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] = (
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY)
            info["ProcessMemoryLimit"] = memory
            win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, info)
            process = win32api.OpenProcess(0x0100 | 0x0001, False, pid)
            try:
                win32job.AssignProcessToJobObject(self.job, process)
            finally:
                process.Close()
        except BaseException:
            self.close()
            raise ServiceError("RESOURCE_ISOLATION_UNAVAILABLE") from None

    def close(self):
        if self.job is not None:
            self.job.Close()
            self.job = None


def _direct_device(value):
    parsed = engine.reference.parse_operand(value, 0) if type(value) is str and len(value) <= 64 else {}
    device = parsed.get("device")
    if (parsed.get("status") != "decoded" or not device or type(device.get("address")) is not int
            or device.get("index") or device.get("indirect") or device.get("digit_width")):
        return None
    return {field: device.get(field) for field in ("family", "address", "module", "word_bit")}


def _reference_identity(value):
    """Bind the engine's structured locator without hashing mutable JSON."""
    if type(value) is not dict or set(value) != {"member", "pou", "row"}:
        return None
    member, pou, row = value["member"], value["pou"], value["row"]
    if (type(member) is not str or re.fullmatch(r"m[0-9]{4,6}", member) is None
            or type(pou) is not str or not 1 <= len(pou) <= 256 or "\x00" in pou
            or type(row) is not int or row < 0):
        return None
    return member, pou, row


def _detail_items(result, project, fields, key, operation):
    """Allowlisted observations only. Never copy an engine object wholesale."""
    source = alias(key, project["sha256"])
    items = []
    pous = result.get("pous", [])
    by_member = {}
    for pou in pous:
        if type(pou) is dict and type(pou.get("member")) is str:
            by_member.setdefault(pou["member"], []).append(pou)

    def locator(kind, member, sequence=None):
        return alias(key, engine.canonical_json([kind, member, sequence]))

    def pou_name(member, observed):
        candidates = by_member.get(member, [])
        if len(candidates) != 1 or candidates[0].get("name") != observed:
            return None
        return observed if "pou_names" in fields else locator("pou", member)

    if operation == "inspect" and "pou_names" in fields:
        for pou in pous:
            if type(pou) is not dict or type(pou.get("member")) is not str:
                continue
            name = pou.get("name") if type(pou.get("name")) is str else None
            items.append({"field": "pou_names", "kind": "pou_name", "source": source,
                          "locator": locator("pou", pou["member"]), "name": name,
                          "rows": pou.get("rows") if type(pou.get("rows")) is int else None,
                          "state": "OBSERVED_SOURCE" if name is not None else "UNRESOLVED"})
    if "device_comments" in fields:
        comments = result.get("device_comments", {})
        groups = {}
        for observed in comments.get("sources", []):
            if type(observed) is dict and type(observed.get("member")) is str:
                groups.setdefault(observed["member"], []).append(observed)
        records = [record for record in comments.get("records", []) if type(record) is dict
                   and type(record.get("member")) is str and _direct_device(record.get("device")) is not None]
        target = _direct_device(result.get("query", {}).get("device")) if operation == "query" else None
        for record in records:
            groups.setdefault(record["member"], [])
        for member, observations in groups.items():
            selected = [record for record in records if record["member"] == member
                        and (operation != "query" or _direct_device(record["device"]) == target)]
            if operation == "query" and not selected:
                continue
            observed = observations[0] if len(observations) == 1 else {}
            bound = observed.get("state") == "OBSERVED_SOURCE"
            count = observed.get("record_count")
            items.append({"field": "device_comments", "kind": "device_comment_source", "source": source,
                          "locator": locator("comment-source", member), "owner": "UNVERIFIED", "scope": "UNVERIFIED",
                          "state": "OBSERVED_SOURCE" if bound else "UNRESOLVED",
                          "record_count": count if type(count) is int and count >= 0 else None,
                          "source_binding_count": len(observations), "native_encoding": None})
            for record in selected:
                sequence = record.get("sequence")
                observed_text = bound and record.get("state") == "OBSERVED_SOURCE"
                items.append({"field": "device_comments", "kind": "device_comment", "source": source,
                              "source_locator": locator("comment-source", member),
                              "locator": locator("comment", member, sequence), "device": record["device"],
                              "text": record.get("text") if observed_text and type(record.get("text")) is str else None,
                              "state": "OBSERVED_SOURCE" if observed_text else "UNRESOLVED", "owner": "UNVERIFIED",
                              "scope": "UNVERIFIED", "native_encoding": None})
    if operation == "inspect" and "text_records" in fields:
        for record in result.get("text_records", []):
            if type(record) is not dict or record.get("kind") not in ("statement", "note"):
                continue
            member, sequence = record.get("member"), record.get("sequence")
            pou = pou_name(member, record.get("pou"))
            bound = pou is not None and type(sequence) is int and sequence >= 0
            raw_type = record.get("raw_type")
            raw_type = raw_type if type(raw_type) is str and re.fullmatch(r"0x[0-9a-fA-F]{2,8}", raw_type) else None
            subtype = record.get("subtype") if record["kind"] == "statement" and record.get("subtype") in ("i", "s") else None
            attachment = record.get("attachment")
            if (type(attachment) is not dict or type(attachment.get("sequence")) is not int
                    or type(attachment.get("opcode")) is not str
                    or re.fullmatch(r"[A-Z0-9_$+*/<>=!\-]{1,32}", attachment["opcode"]) is None):
                attachment = None
            else:
                attachment = {"sequence": attachment["sequence"], "opcode": attachment["opcode"]}
            items.append({"field": "text_records", "kind": record["kind"], "source": source,
                          "locator": locator(record["kind"], member, sequence), "pou": pou,
                          "sequence": sequence if type(sequence) is int and sequence >= 0 else None,
                          "text": record.get("text") if bound and type(record.get("text")) is str else None,
                          "state": record.get("state") if bound and record.get("state") in ("OBSERVED_SOURCE", "UNRESOLVED") else "UNRESOLVED",
                          "raw_type": raw_type if bound else None, "subtype": subtype if bound else None,
                          "subtype_state": "OBSERVED_UI_CORRESPONDENCE_UNVERIFIED" if bound and subtype is not None else "UNRESOLVED",
                          "raw_type_ui_mapping_verified": False, "attachment": attachment if bound else None})
    if "references" in fields:
        matches = set()
        for item in result.get("query", {}).get("matches", []):
            if type(item) is not dict:
                continue
            identity, position = _reference_identity(item.get("locator")), item.get("operand")
            if identity is not None and type(position) is int and position >= 0:
                matches.add((identity, position))
        for occurrence in result.get("references", {}).get("occurrences", []):
            member = occurrence.get("provenance", {}).get("source_store")
            pou = pou_name(member, occurrence.get("pou", {}).get("name"))
            record = occurrence.get("record", {})
            opcode, sequence = record.get("opcode"), record.get("sequence")
            if (pou is None or type(sequence) is not int or type(opcode) is not str or opcode.startswith("<")
                    or re.fullmatch(r"[A-Z0-9_$+*/<>=!\-]{1,32}", opcode) is None):
                continue
            for operand in occurrence.get("operands", []):
                device = _direct_device(operand.get("raw_token"))
                if device is None:
                    continue
                position = operand.get("position")
                if operation == "query":
                    identity = _reference_identity(occurrence.get("provenance", {}).get("source_locator"))
                    if identity is None or type(position) is not int or (identity, position) not in matches:
                        continue
                access = operand.get("access")
                items.append({"field": "references", "kind": "direct_reference", "source": source,
                              "locator": locator("reference", member, [sequence, position]), "pou": pou,
                              "sequence": sequence, "opcode": opcode, "operand": position,
                              "device": device, "access": access if access in ("read", "write", "both", "unknown") else "unknown",
                              "state": "OBSERVED_DIRECT_OPERAND", "complete_search": False})
    return items


def project_result(request):
    """Called only by the gated child after the parent applies the job limit."""
    key, operation = request["alias_key"], request["operation"]
    disclosure = request.get("disclosure", "summary-only")
    grants = [detail_fields(disclosure, project) for project in request["projects"]]
    detail = disclosure == "authorized-detail" and operation in ("inspect", "query")
    policy = engine.Policy(include_text=detail)
    values = []
    for project in request["projects"]:
        data = engine.capture_file(project["path"], expected_sha256=project["sha256"], allow_root=project["root"])
        function = engine.inventory_bytes if operation == "inventory" else engine.analyze_bytes
        if operation == "query":
            value = engine.query_bytes(data, request["device"], policy=policy)
        else:
            value = function(data, policy=policy)
        literals = {candidate["literal"] for candidate in value["cpu"]["candidates"]}
        if not literals or not literals <= {"Q06UDV", "Q06UDVCPU"}:
            reject("PROFILE_LITERAL_MISSING_OR_AMBIGUOUS")
        if operation == "compare":
            values.append(data)
        else:
            values.append(value)
    if operation == "compare":
        result = engine.compare_bytes(*values)
        items = [{"member": alias(key, item["path_sha256"]),
                  "left_present": item["left_member"] is not None,
                  "right_present": item["right_member"] is not None} for item in result["changed_members"]]
        summary = {k: result[k] for k in ("binary", "structure", "supported_observations", "overall_semantic")}
        unknowns = result["unknowns"]
    else:
        result = values[0]
        summary = {"pous": len(result["pous"]), "members": len(result["members"])}
        if operation == "query":
            items = [{"locator": alias(key, engine.canonical_json(item))} for item in result["query"]["matches"]]
            summary.update(matches=len(items), unresolved=len(result["query"]["unresolved"]), complete_search=False)
        else:
            items = [{"pou": alias(key, i), **({"rows": p["rows"]} if "rows" in p else {"bytes": p["bytes"]})}
                     for i, p in enumerate(result["pous"])]
        unknowns = result["unknowns"]
    offset, size = request["offset"], request["page_size"]
    response = {"schema": SCHEMA, "operation": operation, "state": "PARTIAL",
            "overall_semantic": "UNKNOWN", "official_validation": "NOT_RUN",
            "profile_state": "DECLARED_NOT_AUTHENTICATED",
            "engine": alias(key, engine.canonical_json(engine.ENGINE)),
            "sources": [alias(key, p["sha256"]) for p in request["projects"]],
            "summary": summary, "unknowns": unknowns,
            "page": {"offset": offset, "size": size, "total": len(items),
                     "next_offset": offset + size if offset + size < len(items) else None},
            "items": items[offset:offset+size],
            "limits": {"worker_memory_bytes": request["memory_bytes"],
                       "timeout_seconds": request["timeout"], "concurrency": 1}}
    if detail:
        fields = grants[0]
        detail_items = _detail_items(result, request["projects"][0], fields, key, operation)
        response["disclosure"] = {"mode": "authorized-detail", "policy": "authorized-detail/1",
            "granted_fields": list(fields),
            "applied_fields": [field for field in fields if operation == "inspect" or field in ("device_comments", "references")],
            "grant_id": grant_identifier(key, request["project_ids"][0], request["projects"][0], fields)}
        response["detail"] = {"items": detail_items[offset:offset+size],
            "page": {"offset": offset, "size": size, "total": len(detail_items),
                     "next_offset": offset + size if offset + size < len(detail_items) else None},
            "item_count_basis": "TAGGED_FLAT_OBSERVATIONS", "expected_total": None, "complete": False}
    return response


class ReadService:
    def __init__(self, registry):
        self.registry, self.active = registry, False
        self._poisoned = False
        self._owned_proc = self._owned_job = self._owned_waiter = None
        # The operator's separate audit root is a trusted local output. No
        # overwrite, mkdir or fallback next to a source project is permitted.
        self.audit = None
        try:
            before = directory_identity(registry.audit_root)
            self.audit = (registry.audit_root / (uuid.uuid4().hex + ".jsonl")).open("x", encoding="utf-8", newline="\n")
            if directory_identity(registry.audit_root) != before:
                reject("AUDIT_ROOT_CHANGED")
            self.record("SESSION", "OPEN")
        except Exception:
            if self.audit is not None:
                try:
                    self.audit.close()
                except Exception:
                    pass  # A second flush failure must not expose a path.
            raise ServiceError("AUDIT_FAILED") from None

    def record(self, operation, state, *, request_id=None, reason=None, sources=(), grants=()):
        try:
            record = {"operation": operation, "state": state,
                "time_unix_ns": time.time_ns(), "request_id": request_id,
                "policy": self.registry.disclosure + "/1", "config_sha256": self.registry.config_sha256,
                "authority": "operator-pinned-authorized-synthetic", "sources": list(sources),
                "reason": str(ServiceError(reason)) if reason is not None else None}
            if self.registry.disclosure == "authorized-detail":
                record["grant_ids"] = list(grants)
            self.audit.write(engine.canonical_json(record) + "\n")
            self.audit.flush()
            os.fsync(self.audit.fileno())
        except Exception:
            reject("AUDIT_FAILED")

    def close(self):
        if self._poisoned:
            reject("CLEANUP_UNCONFIRMED")
        if not self.audit.closed:
            try:
                self.audit.close()
            except Exception:
                raise ServiceError("AUDIT_FAILED") from None

    async def _cleanup_owned(self):
        """Confirm Job close and bounded wait before releasing owned resources."""
        proc, job = self._owned_proc, self._owned_job
        job_closed = job is None
        if job is not None:
            try:
                job.close()
                job_closed = True
            except Exception:
                pass
        # EOF can terminate a gated child even if killing it is denied.
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except Exception:
            pass
        try:
            if proc.returncode is None:
                proc.kill()
        except Exception:
            pass
        try:
            waiter = asyncio.create_task(proc.wait())
            self._owned_waiter = waiter
            done, _ = await asyncio.wait({waiter}, timeout=CLEANUP_TIMEOUT)
            if not done:
                waiter.cancel()
                return False
            returned = waiter.result()
            return (job_closed and type(returned) is int and type(proc.returncode) is int and
                    returned == proc.returncode)
        except (Exception, asyncio.CancelledError):
            if self._owned_waiter is not None and not self._owned_waiter.done():
                self._owned_waiter.cancel()
            return False

    def reject_call(self, reason="INVALID_ARGUMENTS"):
        self.record("INVALID", "REJECTED", request_id=uuid.uuid4().hex, reason=reason)

    async def execute(self, operation, project_id, *, right_id=None, device=None, offset=0):
        status, reason = "REJECTED", None
        request_id, sources, grants = uuid.uuid4().hex, [], []
        proc, job = None, None
        owns_slot = False
        try:
            if self._poisoned:
                reject("CLEANUP_UNCONFIRMED")
            if (operation not in OPERATIONS or type(project_id) is not str
                    or project_id not in self.registry.projects):
                reject("UNKNOWN_OPERATION_OR_PROJECT")
            if type(offset) is not int or not 0 <= offset <= 1000000:
                reject("INVALID_OFFSET")
            if (operation == "compare") != (right_id is not None):
                reject("INVALID_ARGUMENTS")
            if operation == "compare" and (type(right_id) is not str or right_id not in self.registry.projects):
                reject("UNKNOWN_OPERATION_OR_PROJECT")
            if (operation == "query") != (device is not None):
                reject("INVALID_ARGUMENTS")
            if device is not None:
                parsed = engine.reference.parse_operand(device, 0) if type(device) is str and len(device) <= 64 else {}
                d = parsed.get("device")
                if (parsed.get("status") != "decoded" or not d or d["address"] is None
                        or d["index"] or d["indirect"] or d["digit_width"]):
                    reject("QUERY_REQUIRES_DIRECT_DEVICE")
            selected = [project_id] + ([right_id] if right_id is not None else [])
            for ident in selected:
                project = self.registry.projects[ident]
                fields = detail_fields(self.registry.disclosure, project)
                if self.registry.disclosure == "authorized-detail":
                    grants.append(grant_identifier(self.registry.alias_key, ident, project, fields))
            if self.active:
                reject("BUSY")
            self.active = owns_slot = True
            sources = [self.registry.projects[project_id]["sha256"]]
            if right_id is not None:
                sources.append(self.registry.projects[right_id]["sha256"])
            self.record(operation, "STARTED", request_id=request_id, sources=sources, grants=grants)
            request = {"operation": operation, "projects": [self.registry.projects[project_id]],
                       "alias_key": self.registry.alias_key, "offset": offset,
                       "page_size": self.registry.page_size, "device": device,
                       "timeout": self.registry.timeout, "memory_bytes": self.registry.memory_bytes,
                       "disclosure": self.registry.disclosure, "project_ids": selected}
            if right_id is not None:
                request["projects"].append(self.registry.projects[right_id])
            command, worker_environment = _worker_launch(Path(__file__).with_name("gxw_analysis_worker.py"))
            async with asyncio.timeout(self.registry.timeout):
                proc = await asyncio.create_subprocess_exec(
                    *command, env=worker_environment,
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, limit=RESPONSE_LIMIT+1,
                    creationflags=0x08000000 if sys.platform == "win32" else 0)
                self._owned_proc = proc
                job = WorkerJob(proc.pid, self.registry.memory_bytes)
                self._owned_job = job
                proc.stdin.write(engine.canonical_json(request).encode("ascii") + b"\n")
                await proc.stdin.drain()
                proc.stdin.close()
                data = await proc.stdout.readexactly(4)
                length = int.from_bytes(data, "big")
                if not 0 < length <= RESPONSE_LIMIT:
                    reject("WORKER_RESPONSE_LIMIT")
                payload = await proc.stdout.readexactly(length)
                if await proc.stdout.read(1) or await proc.wait() != 0:
                    reject("WORKER_FAILED")
                result = json.loads(payload)
                if result.get("error"):
                    reject(result["error"])
                if result.get("schema") != SCHEMA:
                    reject("WORKER_RESPONSE_REJECTED")
                status = "PARTIAL"
                return result
        except ServiceError as exc:
            reason = str(exc)
            raise
        except asyncio.CancelledError:
            status = "CANCELLED"
            reason = "CANCELLED"
            raise
        except TimeoutError:
            status = "TIMEOUT"
            reason = "TIMEOUT"
            raise ServiceError("TIMEOUT") from None
        except Exception:
            reason = "WORKER_FAILED"
            raise ServiceError("WORKER_FAILED") from None
        finally:
            # Close only our child job. Drain/reap before releasing concurrency.
            interrupted, cleanup_confirmed = False, proc is None
            try:
                if proc is not None:
                    cleanup = asyncio.create_task(self._cleanup_owned())
                    # A raw Task.cancel can interrupt an outer shield repeatedly.
                    # Keep the cleanup task alive and wait until the owned child
                    # is reaped before propagating the cancellation.
                    while True:
                        try:
                            try:
                                import anyio
                            except ImportError:
                                cleanup_confirmed = await asyncio.shield(cleanup)
                            else:
                                with anyio.CancelScope(shield=True):
                                    cleanup_confirmed = await asyncio.shield(cleanup)
                            break
                        except asyncio.CancelledError:
                            interrupted, status = True, "CANCELLED"
                            reason = "CANCELLED"
                        except Exception:
                            cleanup_confirmed = False
                            break
                    if not cleanup_confirmed:
                        self._poisoned = True
                        status, reason = "REJECTED", "CLEANUP_UNCONFIRMED"
            finally:
                if owns_slot and cleanup_confirmed and not self._poisoned:
                    self._owned_proc = self._owned_job = self._owned_waiter = None
                    self.active = False
                try:
                    self.record(operation if operation in OPERATIONS else "INVALID", status,
                                request_id=request_id, reason=reason, sources=sources, grants=grants)
                except Exception:
                    if not self._poisoned:
                        raise
            if self._poisoned:
                raise ServiceError("CLEANUP_UNCONFIRMED") from None
            if interrupted:
                raise asyncio.CancelledError


class RegisteredArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unrecognized caller arguments verbatim.
        reject("INVALID_ARGUMENTS")


def main(argv=None):
    parser = RegisteredArgumentParser(description="등록한 합성 GXW의 읽기 분석을 실행합니다.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("operation", choices=OPERATIONS)
    parser.add_argument("project_id")
    parser.add_argument("--right-id")
    parser.add_argument("--device")
    parser.add_argument("--offset", type=int, default=0)
    service = None
    try:
        args = parser.parse_args(argv)
        service = ReadService(Registry.load(args.config, args.config_sha256))
        result = asyncio.run(service.execute(args.operation, args.project_id, right_id=args.right_id,
                                             device=args.device, offset=args.offset))
        service.close()
        service = None
        print(engine.canonical_json(result))
        return 0
    except ServiceError as exc:
        print(engine.canonical_json({"schema": SCHEMA, "state": "REJECTED", "reason": str(exc)}))
        return 2
    finally:
        if service is not None:
            try:
                service.close()
            except ServiceError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
