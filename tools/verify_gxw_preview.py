"""GXW 미리보기 wheel을 새 가상환경에 설치하고 합성 계약을 검증합니다.

네트워크 대신 wheelhouse를 사용합니다. 출력, 가상환경과 실패 기록을 보존합니다.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import zipfile

NAME = "gxw-parser-toolkit"
VERSION = "0.2.0a1"
MODULES = (
    "gxw_ladder_reader", "gxw_pou_devmap", "gxw_reference_ir", "gxw_bounded_ole",
    "gxw_bounded_xml", "gxw_parameter_reader", "gxw_project_analysis", "gxw_read_v1",
    "gxw_analysis_service", "gxw_analysis_worker", "gxw_analysis_mcp",
)
SCRIPTS = {
    "gxw-inspect": "gxw_ladder_reader:main", "gxw-analyze": "gxw_project_analysis:main",
    "gxw-reference-ir": "gxw_reference_ir:main", "gxw-read-service": "gxw_analysis_service:main",
    "gxw-read-mcp": "gxw_analysis_mcp:main",
}
TESTS = ("test_read_v1.py", "test_readonly_package.py")
SCHEMA = "schemas/device-references-v1.schema.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def plain_path(path):
    for entry in (path, *path.parents):
        if entry.exists() or entry.is_symlink():
            require(not entry.is_symlink() and not (getattr(entry.lstat(), "st_file_attributes", 0) & 0x400),
                    "링크 경계를 포함한 경로는 사용할 수 없습니다.")


def relative_path(name):
    require(type(name) is str and name != "" and "\\" not in name, "manifest의 상대 경로가 올바르지 않습니다.")
    path = PurePosixPath(name)
    require(not path.is_absolute() and all(part not in (".", "..", "") and ":" not in part for part in path.parts)
            and path.as_posix() == name, "manifest 경로는 정규화한 상대 경로여야 합니다.")
    return path


def read_manifest(path):
    plain_path(path)
    body = path.read_bytes()
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "manifest에 중복 키가 있습니다.")
            result[key] = value
        return result
    record = json.loads(body, object_pairs_hook=unique)
    require(type(record) is dict, "manifest 최상위는 객체여야 합니다.")
    require(record.get("format") == "gxw-parser-toolkit.preview-build/1"
            and record.get("distribution") == NAME and record.get("version") == VERSION,
            "지원하는 미리보기 manifest가 아닙니다.")
    require(type(record.get("modules")) is list and len(record["modules"]) == len(MODULES)
            and set(record["modules"]) == set(MODULES) and record.get("scripts") == SCRIPTS,
            "manifest의 읽기 전용 모듈과 진입점이 일치하지 않습니다.")
    for key in ("source_commit", "source_tree", "package_tree"):
        require(type(record.get(key)) is str and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", record[key]),
                "커밋 또는 트리 식별자가 올바르지 않습니다.")
    inputs = {}
    require(type(record.get("inputs")) is list and type(record.get("artifacts")) is list,
            "manifest 입력과 산출물 목록이 필요합니다.")
    for item in record["inputs"]:
        require(type(item) is dict, "입력 파일 식별자는 객체여야 합니다.")
        name = relative_path(item.get("path")).as_posix()
        require(name not in inputs and type(item.get("bytes")) is int and item["bytes"] >= 0
                and type(item.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
                "입력 파일 식별자가 올바르지 않습니다.")
        inputs[name] = item
    required = {"pyproject.toml", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", SCHEMA,
                *(f"src/{module}.py" for module in MODULES), *(f"tests/{name}" for name in TESTS)}
    require(required <= inputs.keys() and all(name in required or (PurePosixPath(name).name == name
            and name.lower().startswith("readme")) for name in inputs), "선별한 패키지 입력 집합이 일치하지 않습니다.")
    artifacts = []
    for item in record["artifacts"]:
        require(type(item) is dict, "산출물 식별자는 객체여야 합니다.")
        relative = relative_path(item.get("path"))
        require(len(relative.parts) == 2 and relative.parts[0] == "artifacts", "산출물 상대 경로가 올바르지 않습니다.")
        artifact = path.parent.joinpath(*relative.parts)
        plain_path(artifact)
        data = artifact.read_bytes()
        require(type(item.get("bytes")) is int and len(data) == item["bytes"] and sha(data) == item.get("sha256"),
                "산출물의 크기 또는 SHA-256이 일치하지 않습니다.")
        artifacts.append(artifact)
    require(len(artifacts) == 2 and len(set(artifacts)) == 2, "서로 다른 산출물 두 개가 필요합니다.")
    wheels = [a for a in artifacts if a.suffix == ".whl"]
    sources = [a for a in artifacts if a.name.endswith(".tar.gz")]
    require(len(wheels) == len(sources) == 1, "wheel과 sdist가 각각 하나 필요합니다.")
    return record, inputs, wheels[0], sources[0], sha(body)


def check_payload(name, body, inputs):
    require(name in inputs and len(body) == inputs[name]["bytes"] and sha(body) == inputs[name]["sha256"],
            "패키지 입력의 크기 또는 SHA-256이 일치하지 않습니다.")


def archive_inputs(wheel, source, inputs):
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "wheel에 중복 경로가 있습니다.")
        for name in names:
            relative_path(name.rstrip("/"))
        require({name for name in names if name.endswith(".py")} == {module + ".py" for module in MODULES},
                "wheel의 읽기 전용 모듈 집합이 일치하지 않습니다.")
        for module in MODULES:
            check_payload(f"src/{module}.py", archive.read(module + ".py"), inputs)
        schemas = [name for name in names if name.endswith("/share/gx-project-toolkit/" + PurePosixPath(SCHEMA).name)]
        require(len(schemas) == 1, "wheel 스키마가 없습니다.")
        check_payload(SCHEMA, archive.read(schemas[0]), inputs)
    with tarfile.open(source, "r:gz") as archive:
        members = archive.getmembers()
        require(len({m.name for m in members}) == len(members) and members, "sdist 경로가 중복되거나 비어 있습니다.")
        for member in members:
            relative_path(member.name.rstrip("/"))
            require(member.isfile() or member.isdir(), "sdist 링크와 특수 파일은 지원하지 않습니다.")
        roots = {PurePosixPath(m.name).parts[0] for m in members}
        require(len(roots) == 1, "sdist 최상위 경로가 일치하지 않습니다.")
        files = {str(PurePosixPath(m.name).relative_to(next(iter(roots)))): m for m in members if m.isfile()}
        require({name for name in files if name.endswith(".py")} == {name for name in inputs if name.endswith(".py")},
                "sdist의 모듈과 합성 시험 집합이 일치하지 않습니다.")
        selected = {}
        for name in inputs:
            require(name in files, "sdist에 필요한 입력이 없습니다.")
            body = archive.extractfile(files[name]).read()
            check_payload(name, body, inputs)
            selected[name] = body
    return selected


INSTALL_CHECK = r'''
import hashlib, importlib, importlib.metadata as md, importlib.util, json, sys
from pathlib import Path
expected = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert sys.prefix != sys.base_prefix, "새 가상환경이 필요합니다."
assert not __import__("site").ENABLE_USER_SITE, "사용자 패키지 경로가 활성화됐습니다."
prefix = Path(sys.prefix).resolve()
dist = md.distribution("gxw-parser-toolkit")
assert dist.metadata["Name"] == "gxw-parser-toolkit" and dist.version == "0.2.0a1", "설치 이름 또는 버전이 일치하지 않습니다."
url = json.loads(dist.read_text("direct_url.json") or "{}")
assert "dir_info" not in url and "archive_info" in url, "wheel 설치가 필요합니다."
assert url["archive_info"].get("hashes", {}).get("sha256") == expected["wheel_sha256"], "설치 wheel 식별자가 다릅니다."
entries = [e for e in dist.entry_points if e.group == "console_scripts"]
scripts = {e.name: e.value for e in entries}
assert len(entries) == len(expected["scripts"]) and scripts == expected["scripts"], "설치 진입점이 다릅니다."
script_dir = prefix / ("Scripts" if sys.platform == "win32" else "bin")
assert {p.stem if sys.platform == "win32" else p.name for p in script_dir.glob("gxw-*")} == set(expected["scripts"]), "예상하지 않은 CLI가 설치됐습니다."
files = list(dist.files or ())
assert {str(f) for f in files if str(f).endswith(".py")} == {name + ".py" for name in expected["modules"]}, "설치 모듈 집합이 다릅니다."
origins = {}
for name in expected["modules"]:
    module = importlib.import_module(name)
    path = Path(module.__file__).resolve(strict=True)
    assert path == Path(dist.locate_file(name + ".py")).resolve() and path.is_relative_to(prefix), "설치 경계 밖의 모듈입니다."
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected["inputs"]["src/" + name + ".py"]["sha256"], "설치 모듈의 바이트가 다릅니다."
    origins[name] = path.relative_to(prefix).as_posix()
for name in ("gxw_ladder_writer", "gxw_single_command", "gxw_parameter_records", "wt9_fill_pou_body"):
    assert importlib.util.find_spec(name) is None, "제외한 모듈이 설치돼 있습니다."
try:
    md.distribution("gx-project-toolkit-readonly")
except md.PackageNotFoundError:
    pass
else:
    raise AssertionError("다른 읽기 전용 배포물이 함께 설치돼 있습니다.")
import gxw_parameter_reader as parameters
assert not hasattr(parameters, "encode_records") and not hasattr(parameters, "replace_ascii_label"), "쓰기 API가 포함됐습니다."
schema_files = [f for f in files if str(f).replace("\\", "/").endswith("share/gx-project-toolkit/device-references-v1.schema.json")]
assert len(schema_files) == 1, "설치 스키마가 없습니다."
schema = Path(dist.locate_file(schema_files[0])).resolve(strict=True)
assert schema.is_relative_to(prefix), "설치 스키마 경계가 다릅니다."
assert hashlib.sha256(schema.read_bytes()).hexdigest() == expected["inputs"]["schemas/device-references-v1.schema.json"]["sha256"], "스키마 바이트가 다릅니다."
assert json.loads(schema.read_bytes())["properties"]["complete_search"]["const"] is False
for name, module in tuple(sys.modules.items()):
    if name.startswith("gxw_") and getattr(module, "__file__", None):
        assert Path(module.__file__).resolve().is_relative_to(prefix), "읽기 모듈의 외부 의존성이 발견됐습니다."
print(json.dumps({"status": "PASS", "distribution": dist.metadata["Name"], "version": dist.version,
                  "modules": origins, "scripts": scripts, "schema": schema.relative_to(prefix).as_posix(),
                  "dependencies": sorted({d.metadata["Name"] + "==" + d.version for d in md.distributions()})}, sort_keys=True))
'''

TEST_RUNNER = r'''
import importlib.util, json, sys, unittest
from pathlib import Path
root = Path(sys.argv[1])
suite = unittest.TestSuite()
for name in ("test_read_v1", "test_readonly_package"):
    spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
result = unittest.TextTestRunner(verbosity=2).run(suite)
assert result.testsRun > 0 and not result.skipped, "실행되지 않은 합성 시험이 있습니다."
assert result.wasSuccessful(), "합성 시험이 실패했습니다."
print(json.dumps({"status": "PASS", "tests": result.testsRun, "skipped": len(result.skipped)}))
'''

MCP_CHECK = r'''
import asyncio, hashlib, json, os, sys
from pathlib import Path
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
root = Path(sys.argv[1])
inputs, audit = root / "inputs", root / "audit"
inputs.mkdir(); audit.mkdir()
sample = inputs / "sample.gxw"
sample.write_bytes(b"synthetic configuration-only input\n")
config = {"schema": "plcman.gxw.readonly-config/1", "disclosure": "summary-only", "alias_key": "ab" * 32,
          "audit_root": str(audit), "projects": {"sample": {"path": str(sample), "root": str(inputs),
          "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(), "profile": "q06udv-simple-ladder-observed",
          "authority": "authorized-synthetic"}}}
payload = json.dumps(config, sort_keys=True).encode("utf-8")
config_file = root / "config.json"
with config_file.open("xb") as stream: stream.write(payload)
async def check():
    params = StdioServerParameters(command=sys.executable, env=dict(os.environ), args=["-I", "-B", "-m", "gxw_analysis_mcp",
        "--config", str(config_file), "--config-sha256", hashlib.sha256(payload).hexdigest()])
    async with asyncio.timeout(30):
        async with stdio_client(params) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                assert {t.name for t in tools} == {"inventory", "inspect", "reference_query", "compare"}
                for tool in tools:
                    assert tool.annotations.read_only_hint is True and tool.annotations.destructive_hint is False
                    assert tool.input_schema["additionalProperties"] is False
                for arguments in ({"project_id": "unregistered"}, {"project_id": "sample", "include_text": True}):
                    result = await session.call_tool("inspect", arguments)
                    assert result.is_error is True
                    if "include_text" not in arguments:
                        assert result.content[0].text == "UNKNOWN_OPERATION_OR_PROJECT"
    records = [json.loads(line) for path in audit.iterdir() for line in path.read_text(encoding="utf-8").splitlines()]
    assert any(r["state"] == "REJECTED" for r in records)
    assert not any(r["state"] == "STARTED" for r in records), "미등록 요청이 실행됐습니다."
    print(json.dumps({"status": "PASS", "transport": "stdio", "tools": 4, "rejected_calls": 2,
                      "project_analysis": "NOT_RUN"}))
asyncio.run(check())
'''


def verify(manifest, output, wheelhouse):
    manifest = Path(os.path.abspath(manifest))
    record, inputs, wheel, source, manifest_sha = read_manifest(manifest)
    selected = archive_inputs(wheel, source, inputs)
    wheelhouse = Path(os.path.abspath(wheelhouse))
    plain_path(wheelhouse)
    require(wheelhouse.is_dir(), "오프라인 의존성을 담은 wheelhouse가 필요합니다.")
    output = Path(os.path.abspath(output))
    plain_path(output)
    require(not output.exists() and not output.resolve().is_relative_to(manifest.parent.resolve())
            and not output.resolve().is_relative_to(wheelhouse.resolve()), "입력 경로 밖의 새 검증 출력 경로를 지정하십시오.")
    checkout = Path(__file__).resolve().parents[1]
    require(not output.resolve().is_relative_to(checkout), "체크아웃 밖의 새 검증 출력 경로를 지정하십시오.")
    output.mkdir(parents=True, exist_ok=False)
    temporary, runtime, tests = output / "temp", output / "runtime", output / "tests"
    for directory in (temporary, runtime, tests):
        directory.mkdir()
    for name in TESTS:
        with (tests / name).open("xb") as stream:
            stream.write(selected["tests/" + name])
    expected = {"modules": list(MODULES), "scripts": SCRIPTS, "inputs": inputs, "wheel_sha256": sha(wheel.read_bytes())}
    expected_file = output / "expected.json"
    with expected_file.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(expected, stream, sort_keys=True)
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "PIP_"))}
    environment.update(TEMP=str(temporary), TMP=str(temporary), TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE="1",
                       PYTHONNOUSERSITE="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
                       PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_CACHE_DIR="1")
    def command(label, args, expected_code=0):
        with (output / (label + ".stdout")).open("xb") as stdout, (output / (label + ".stderr")).open("xb") as stderr:
            completed = subprocess.run(args, cwd=runtime, env=environment, stdout=stdout, stderr=stderr, timeout=300)
        if completed.returncode != expected_code:
            with (output / "failure.json").open("x", encoding="utf-8", newline="\n") as stream:
                json.dump({"status": "FAILED", "stage": label, "exit": completed.returncode,
                           "expected_exit": expected_code}, stream, sort_keys=True)
                stream.write("\n")
        require(completed.returncode == expected_code, "검증 단계가 실패했습니다. 출력 경로의 기록을 확인하십시오: " + label)
        return (output / (label + ".stdout")).read_bytes()
    environment_root = output / "venv"
    # venv owns its bootstrap temporary files; redirect only this child process.
    command("create-venv", [sys.executable, "-I", "-B", "-m", "venv", str(environment_root)])
    executable_dir = environment_root / ("Scripts" if os.name == "nt" else "bin")
    python = executable_dir / ("python.exe" if os.name == "nt" else "python")
    command("install", [str(python), "-I", "-B", "-m", "pip", "--isolated", "install", "--no-index",
                        "--no-cache-dir", "--find-links", str(wheelhouse), str(wheel) + "[mcp]"])
    installed = json.loads(command("installed", [str(python), "-I", "-B", "-c", INSTALL_CHECK, str(expected_file)]))
    cli = {}
    for name in SCRIPTS:
        script = executable_dir / (name + (".exe" if os.name == "nt" else ""))
        require(script.is_file(), "설치한 CLI 실행 파일이 없습니다.")
        code = 1 if name == "gxw-inspect" else 0
        stdout = command(name + "-help", [str(script), "--help"], code)
        require(b"--help" in stdout and b"usage:" in stdout, "CLI 도움말 출력이 올바르지 않습니다.")
        cli[name] = {"status": "PASS", "exit_code": code, "stdout_sha256": sha(stdout)}
    synthetic = json.loads(command("synthetic", [str(python), "-I", "-B", "-c", TEST_RUNNER, str(tests)]))
    mcp_root = runtime / "mcp"
    mcp_root.mkdir()
    mcp = json.loads(command("mcp", [str(python), "-I", "-B", "-c", MCP_CHECK, str(mcp_root)]))
    result = {"format": "gxw-parser-toolkit.preview-verification/1", "status": "PASS",
              "distribution": NAME, "version": VERSION, "build_manifest_sha256": manifest_sha,
              "source_commit": record["source_commit"], "source_tree": record["source_tree"],
              "package_tree": record["package_tree"], "artifacts": record["artifacts"],
              "installed": installed, "cli": cli, "synthetic": synthetic, "mcp": mcp,
              "native_execution": "NOT_RUN", "product_acceptance": "NOT_GRANTED", "published": False}
    with (output / "verification.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--manifest", type=Path, required=True, help="빌드 manifest 경로")
    parser.add_argument("--output", type=Path, required=True, help="입력과 체크아웃 밖의 새 출력 경로")
    parser.add_argument("--wheelhouse", type=Path, required=True, help="의존성 wheel을 담은 오프라인 경로")
    args = parser.parse_args(argv)
    try:
        result = verify(args.manifest, args.output, args.wheelhouse)
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError):
        print("검증을 완료하지 못했습니다. 입력과 출력 경로의 기록을 확인하십시오.", file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "distribution": NAME, "version": VERSION,
                      "modules": len(MODULES), "scripts": len(SCRIPTS), "tests": result["synthetic"]["tests"],
                      "mcp": result["mcp"]["status"], "published": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
