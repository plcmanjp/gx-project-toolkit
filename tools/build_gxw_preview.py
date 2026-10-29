"""커밋된 독립 체크아웃에서 GXW 읽기 전용 미리보기 배포물을 만듭니다.

기존 출력은 보존합니다. 의존성 설치, 소스 수정과 공개 발행은 수행하지 않습니다.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tomllib
import zipfile

NAME = "gxw-parser-toolkit"
VERSION = "0.2.0a1"
PACKAGE = "packages/gxw-q"
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
LICENSES = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
SCHEMA = "schemas/device-references-v1.schema.json"
FORMAT = "gxw-parser-toolkit.preview-build/1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def plain_path(path):
    for entry in (path, *path.parents):
        if entry.exists() or entry.is_symlink():
            require(not entry.is_symlink() and not (getattr(entry.lstat(), "st_file_attributes", 0) & 0x400),
                    "링크 경계를 포함한 경로는 사용할 수 없습니다.")


def git_environment():
    blocked = {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
               "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
               "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES",
               "GIT_DISCOVERY_ACROSS_FILESYSTEM"}
    require(not any(k.upper() in blocked or k.upper().startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
                    for k in os.environ), "Git 경로 또는 설정 재정의 환경변수를 해제하십시오.")
    result = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    result.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    return result


def git(root, *args):
    result = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                             "-c", "core.untrackedCache=false", "-C", str(root), *args],
                            env=git_environment(), capture_output=True, timeout=120)
    require(result.returncode == 0, "독립 Git 체크아웃의 커밋 정보를 읽지 못했습니다.")
    return result.stdout


def source_scope(root):
    root = Path(os.path.abspath(root))
    plain_path(root)
    root = root.resolve(strict=True)
    repository = Path(git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve(strict=True)
    require(root == repository, "저장소 최상위의 독립 체크아웃을 지정하십시오.")
    metadata = root / ".git"
    require(metadata.is_dir(), "공유 작업 트리 대신 독립 체크아웃이 필요합니다.")
    plain_path(metadata)
    require(not (metadata / "objects/info/alternates").exists() and not (metadata / "commondir").exists(),
            "공유 Git 객체 저장소는 사용할 수 없습니다.")
    for path in metadata.rglob("*"):
        plain_path(path)
        if path.is_file() and path.is_relative_to(metadata / "objects"):
            require(path.stat().st_nlink == 1, "공유 Git 객체 파일은 사용할 수 없습니다.")
    for arguments in (("rev-parse", "--absolute-git-dir"),
                      ("rev-parse", "--path-format=absolute", "--git-common-dir")):
        require(Path(git(root, *arguments).decode("utf-8").strip()).resolve() == metadata,
                "Git 메타데이터 경계가 일치하지 않습니다.")
    require(not git(root, "status", "--porcelain", "--untracked-files=all"),
            "검토한 변경을 커밋한 뒤 깨끗한 체크아웃에서 실행하십시오.")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    package_tree = git(root, "rev-parse", f"{commit}:{PACKAGE}").decode().strip()
    epoch = int(git(root, "show", "-s", "--format=%ct", commit).decode().strip())
    entries = {}
    for row in git(root, "ls-tree", "-rz", tree).split(b"\0"):
        if not row:
            continue
        meta, raw_name = row.split(b"\t", 1)
        mode, kind, oid = meta.split()
        name = raw_name.decode("utf-8")
        relative = PurePosixPath(name)
        require(mode in (b"100644", b"100755") and kind == b"blob" and not relative.is_absolute()
                and ".." not in relative.parts and "\\" not in name, "일반 파일 커밋만 지원합니다.")
        entries[name] = oid.decode()
    return root, commit, tree, package_tree, epoch, entries


def write_new(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(body)


def package_inputs(root, entries):
    def committed(name):
        require(name in entries, "배포에 필요한 커밋 파일이 없습니다.")
        return git(root, "cat-file", "blob", entries[name])
    config = tomllib.loads(committed(f"{PACKAGE}/pyproject.toml").decode("utf-8"))
    project = config.get("project", {})
    require(project.get("name") == NAME and project.get("version") == VERSION,
            "배포 이름 또는 미리보기 버전이 일치하지 않습니다.")
    require(project.get("scripts") == SCRIPTS, "읽기 전용 진입점 다섯 개가 필요합니다.")
    settings = config.get("tool", {}).get("setuptools", {})
    require(not (set(settings) - {"package-dir", "py-modules", "data-files", "include-package-data", "license-files"}),
            "선별한 모듈과 스키마 이외의 설치 설정은 지원하지 않습니다.")
    declared = settings.get("py-modules", [])
    require(len(declared) == len(MODULES) and set(declared) == set(MODULES)
            and settings.get("package-dir") == {"": "src"}, "읽기 전용 모듈 열한 개가 필요합니다.")
    require(settings.get("data-files") == {"share/gx-project-toolkit": [SCHEMA]},
            "설치할 참조 스키마 경로가 일치하지 않습니다.")
    require(config.get("build-system", {}).get("build-backend") == "setuptools.build_meta"
            and "backend-path" not in config.get("build-system", {}), "표준 setuptools 빌드만 지원합니다.")
    paths = ["pyproject.toml", SCHEMA, *(f"src/{module}.py" for module in MODULES),
             *(f"tests/{name}" for name in TESTS)]
    readme = project.get("readme")
    if readme is not None:
        readme = readme.get("file") if isinstance(readme, dict) else readme
        require(type(readme) is str and PurePosixPath(readme).name == readme and readme.lower().startswith("readme"),
                "패키지 안의 README 파일만 사용할 수 있습니다.")
        paths.append(readme)
    result = {path: committed(f"{PACKAGE}/{path}") for path in paths}
    result.update({name: committed(name) for name in LICENSES})
    return result


def check_archives(artifacts, inputs):
    wheels = [p for p in artifacts if p.suffix == ".whl"]
    sources = [p for p in artifacts if p.name.endswith(".tar.gz")]
    require(len(artifacts) == 2 and len(wheels) == len(sources) == 1, "wheel과 sdist가 각각 하나 필요합니다.")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "wheel에 중복 경로가 있습니다.")
        require({name for name in names if name.endswith(".py")} == {f"{m}.py" for m in MODULES},
                "wheel의 읽기 전용 모듈 집합이 일치하지 않습니다.")
        for module in MODULES:
            require(archive.read(module + ".py") == inputs[f"src/{module}.py"], "wheel 모듈의 바이트가 달라졌습니다.")
        schemas = [name for name in names if name.endswith("/share/gx-project-toolkit/" + PurePosixPath(SCHEMA).name)]
        require(len(schemas) == 1 and archive.read(schemas[0]) == inputs[SCHEMA], "wheel 스키마가 일치하지 않습니다.")
    with tarfile.open(sources[0], "r:gz") as archive:
        members = archive.getmembers()
        require(len({m.name for m in members}) == len(members), "sdist에 중복 경로가 있습니다.")
        roots = {PurePosixPath(m.name).parts[0] for m in members}
        require(len(roots) == 1, "sdist 최상위 경로가 일치하지 않습니다.")
        files = {str(PurePosixPath(m.name).relative_to(next(iter(roots)))): m for m in members if m.isfile()}
        require(all(m.isfile() or m.isdir() for m in members), "sdist 링크는 지원하지 않습니다.")
        require({name for name in files if name.endswith(".py")} ==
                {name for name in inputs if name.endswith(".py")}, "sdist의 모듈 또는 합성 시험 집합이 일치하지 않습니다.")
        for name, body in inputs.items():
            require(name in files and archive.extractfile(files[name]).read() == body, "sdist 입력의 바이트가 달라졌습니다.")


def build(root, output):
    root, commit, tree, package_tree, epoch, entries = source_scope(root)
    inputs = package_inputs(root, entries)
    output = Path(os.path.abspath(output))
    plain_path(output)
    require(not output.exists() and not output.is_relative_to(root) and not output.resolve().is_relative_to(root),
            "체크아웃 밖의 새 출력 경로를 지정하십시오.")
    versions = {name: importlib.metadata.version(name) for name in ("build", "setuptools", "packaging", "pyproject_hooks")}
    output.mkdir(parents=True, exist_ok=False)
    stage, artifacts, temporary = output / "staging/gxw-q", output / "artifacts", output / "temp"
    stage.mkdir(parents=True)
    artifacts.mkdir()
    temporary.mkdir()
    for name, body in inputs.items():
        write_new(stage / name, body)
    for path in stage.rglob("*"):
        os.utime(path, (epoch, epoch))
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "PIP_"))}
    environment.update(SOURCE_DATE_EPOCH=str(epoch), PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1",
                       TEMP=str(temporary), TMP=str(temporary), TMPDIR=str(temporary), PIP_NO_INDEX="1")
    with (output / "build.stdout").open("xb") as out, (output / "build.stderr").open("xb") as err:
        completed = subprocess.run([sys.executable, "-I", "-B", "-m", "build", "--no-isolation", "--wheel", "--sdist",
                                    "--outdir", str(artifacts), str(stage)], env=environment, stdout=out, stderr=err,
                                   timeout=300)
    require(completed.returncode == 0, "빌드가 실패했습니다. 출력 경로의 기록을 확인하십시오.")
    artifact_files = sorted(artifacts.iterdir())
    check_archives(artifact_files, inputs)
    require(not git(root, "status", "--porcelain", "--untracked-files=all")
            and git(root, "rev-parse", "HEAD").decode().strip() == commit,
            "빌드 중 원본 체크아웃의 상태가 변경됐습니다.")
    result = {"format": FORMAT, "distribution": NAME, "version": VERSION, "source_commit": commit,
              "source_tree": tree, "package_tree": package_tree, "source_date_epoch": epoch,
              "python": sys.version, "platform": sys.platform, "build_tools": versions,
              "modules": list(MODULES), "scripts": SCRIPTS,
              "inputs": [{"path": name, "bytes": len(body), "sha256": digest(body)} for name, body in sorted(inputs.items())],
              "artifacts": [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size,
                             "sha256": digest(p.read_bytes())} for p in artifact_files], "published": False}
    write_new(output / "build-manifest.json", (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1], help="커밋된 독립 체크아웃")
    parser.add_argument("--output", type=Path, required=True, help="체크아웃 밖의 새 출력 경로")
    args = parser.parse_args(argv)
    try:
        result = build(args.source, args.output)
    except (ValueError, OSError, subprocess.SubprocessError, importlib.metadata.PackageNotFoundError) as error:
        print("빌드를 완료하지 못했습니다: " + (str(error) if isinstance(error, ValueError) else "입력, 빌드 환경과 기록을 확인하십시오."), file=sys.stderr)
        return 2
    print(json.dumps({"status": "BUILT", "distribution": NAME, "version": VERSION,
                      "source_commit": result["source_commit"], "artifacts": len(result["artifacts"]), "published": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
