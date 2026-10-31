"""Private child entry point. No site/PTH/parser imports before a valid gate."""
import sys


def main():
    line = sys.stdin.buffer.readline(65537)
    if not line.endswith(b"\n") or len(line) > 65536 or sys.stdin.buffer.read(1):
        return 2
    import json

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def constant(_):
        raise ValueError

    try:
        request = json.loads(line.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=constant)
        required = {"operation", "projects", "alias_key", "offset", "page_size", "device", "timeout",
                    "memory_bytes", "disclosure", "project_ids"}
        if (type(request) is not dict or set(request) != required or
                request["operation"] not in ("inventory", "inspect", "query", "compare") or
                type(request["projects"]) is not list or len(request["projects"]) != (2 if request["operation"] == "compare" else 1) or
                type(request["alias_key"]) is not str or len(request["alias_key"]) != 64 or
                any(c not in "0123456789abcdef" for c in request["alias_key"]) or
                type(request["offset"]) is not int or not 0 <= request["offset"] <= 1000000 or
                type(request["page_size"]) is not int or not 1 <= request["page_size"] <= 200 or
                type(request["timeout"]) not in (int, float) or not 0.1 <= request["timeout"] <= 60 or
                type(request["memory_bytes"]) is not int or not 32 * 1024 * 1024 <= request["memory_bytes"] <= 1024 ** 3 or
                request["disclosure"] not in ("summary-only", "authorized-detail") or
                type(request["project_ids"]) is not list or len(request["project_ids"]) != len(request["projects"]) or
                any(type(value) is not str or not value or len(value) > 48 for value in request["project_ids"]) or
                (request["operation"] == "query" and (type(request["device"]) is not str or len(request["device"]) > 64)) or
                (request["operation"] != "query" and request["device"] is not None)):
            return 2
        for project in request["projects"]:
            fields = {"path", "root", "sha256", "profile", "authority"}
            if (type(project) is not dict or not fields <= set(project) or set(project) - fields - {"detail_fields"} or
                    any(type(project[k]) is not str for k in fields) or
                    not 1 <= len(project["path"]) <= 32768 or not 1 <= len(project["root"]) <= 32768 or
                    len(project["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in project["sha256"]) or
                    project["profile"] != "q06udv-simple-ladder-observed" or project["authority"] != "authorized-synthetic"):
                return 2
        import os
        from pathlib import Path
        raw_site = os.environ.get("GXW_TOOLKIT_WORKER_SITE")
        if type(raw_site) is not str or not 1 <= len(raw_site) <= 32768 or not Path(raw_site).is_absolute():
            return 2
        runtime_site = Path(raw_site).resolve(strict=True)
        if not runtime_site.is_dir() or runtime_site.name.lower() != "site-packages":
            return 2
        import site
        site.addsitedir(str(runtime_site))
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import gxw_analysis_service as service
    except Exception:
        return 2
    try:
        result = service.project_result(request)
    except service.engine.AnalysisError as exc:
        result = {"error": str(exc)}
    except service.ServiceError as exc:
        result = {"error": str(exc)}
    except MemoryError:
        result = {"error": "MEMORY_LIMIT"}
    except Exception:
        result = {"error": "DECODE_REJECTED"}
    body = service.engine.canonical_json(result).encode("ascii")
    if len(body) > service.RESPONSE_LIMIT:
        body = b'{"error":"WORKER_RESPONSE_LIMIT"}'
    sys.stdout.buffer.write(len(body).to_bytes(4, "big") + body)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
