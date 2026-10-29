"""Private child entry point. Wait for the parent's resource gate before imports."""
import sys


def main():
    # No parser/project imports or file access until the parent assigns a job.
    line = sys.stdin.buffer.readline(65537)
    if not line.endswith(b"\n") or len(line) > 65536:
        return 2
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    import json
    import gxw_analysis_service as service
    try:
        result = service.project_result(json.loads(line))
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
