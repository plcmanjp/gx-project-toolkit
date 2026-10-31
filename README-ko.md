# GX Project Toolkit

[English](README.md) | [한국어](README-ko.md)

지원되는 Mitsubishi GX Works2(`.gxw`)와 GX Works3(`.gx3`) 프로젝트 파일을 오프라인에서 읽고 분석하는 도구입니다. 형식별 지원 범위 안에서 프로그램 구조, 래더 명령, 디바이스 참조와 주석을 텍스트, CSV 또는 JSON으로 확인할 수 있습니다.

현재 GXW 배포본은 **[0.2.0a2 읽기 전용 프리뷰](https://github.com/plcmanjp/gx-project-toolkit/releases/tag/gxw-v0.2.0a2)**입니다. 로컬 읽기 서비스와 stdio MCP도 제공합니다. 프로젝트 파일을 수정하거나 GX Works를 실행하지 않으며 PLC에 연결하지 않습니다.

## 지원 형식

| 입력 | 패키지와 현재 소스 버전 | 지원 범위 |
| --- | --- | --- |
| GX Works2 `.gxw` | `gxw-parser-toolkit 0.2.0a2` | Q06UDV Simple/Ladder의 직접 Boolean 및 MOV/DMOV 구조화 분석, 목록/참조 조회와 비교, CSV/JSON과 로컬 CLI/MCP |
| GX Works3 `.gx3`, FX5 | `gx3-fx5-parser-toolkit 0.4.1` | 지원되는 FX5 프로젝트 구조, 래더 레코드와 디바이스 참조 분석 |
| GX Works3 `.gx3`, iQ-R | `gx3-r-parser-toolkit 0.2.0` | `R04/4097`의 R04CPU Ladder 프로필, 프로그램 레코드, 읽을 수 있는 주석/라벨과 디바이스 참조 출력 |

GXW는 프리뷰 패키지를 내려받아 설치합니다. FX5와 iQ-R 패키지는 아래 절차로 소스에서 빌드합니다. 지원 대상은 [호환성 표](docs/compatibility-matrix-ko.md)에 명시한 프로필과 형식으로 제한되며 모든 CPU, 명령, 언어 또는 프로젝트 설정을 포함하지 않습니다.

## GXW 프리뷰 시작하기

Python 3.12 이상이 필요하며 예제는 Windows PowerShell 기준입니다. `python --version`이 3.12 이상을 가리키는지 확인하고, 필요하면 `python`을 설치된 버전의 런처(예: `py -3.13`)로 바꾸세요. 등록된 GXW 서비스와 MCP는 Windows가 필요합니다.

설치 시 런타임 의존성인 `olefile`과 Windows의 `pywin32`를 내려받으며 MCP는 `mcp`를 추가합니다. 설치에는 인터넷 연결이나 미리 준비한 의존성 wheelhouse가 필요하고 분석 자체는 오프라인에서 실행됩니다. 예제의 `.gxw`와 `.gx3` 파일은 제공하지 않으므로 사용 권한이 있는 프로젝트 사본을 별도로 준비해야 합니다.

1. [배포 페이지](https://github.com/plcmanjp/gx-project-toolkit/releases/tag/gxw-v0.2.0a2)에서 `gxw_parser_toolkit-0.2.0a2-py3-none-any.whl`을 로컬 `downloads` 폴더로 내려받습니다.
2. 새 가상환경을 만들고 내려받은 wheel을 설치합니다. 다른 GXW 패키지 버전과 환경을 분리합니다.

```powershell
python -m venv .venv-gxw
$gxwPython = (Resolve-Path '.\.venv-gxw\Scripts\python.exe').Path
& $gxwPython -m pip install '.\downloads\gxw_parser_toolkit-0.2.0a2-py3-none-any.whl'
& $gxwPython -m gxw_project_analysis --help
```

Windows에서 MCP를 사용하려면 같은 환경에 선택 의존성도 설치합니다. 현재 등록 계약은 사용 권한이 있는 합성 프로젝트만 허용합니다. 자세한 설정은 아래 요약과 한글 사용법 문서를 참고하세요.

```powershell
& $gxwPython -m pip install '.\downloads\gxw_parser_toolkit-0.2.0a2-py3-none-any.whl[mcp]'
```

### 프로젝트 분석하기

`sample.gxw`를 사용 권한이 있는 로컬 프로젝트 사본으로 바꿉니다. SHA-256 인자는 분석할 파일을 고정하고 `--allow-root`는 입력 디렉터리를 제한합니다. 예제의 `python -m gxw_project_analysis`는 CLI의 `gxw-analyze`와 같은 인터페이스입니다.

```powershell
$gxwInput = (Resolve-Path '.\sample.gxw').Path
$gxwRoot = Split-Path -Parent $gxwInput
$gxwSha = (Get-FileHash -LiteralPath $gxwInput -Algorithm SHA256).Hash.ToLowerInvariant()

& $gxwPython -m gxw_project_analysis inventory $gxwInput --sha256 $gxwSha --allow-root $gxwRoot
& $gxwPython -m gxw_project_analysis inspect $gxwInput --sha256 $gxwSha --allow-root $gxwRoot
& $gxwPython -m gxw_project_analysis query $gxwInput --sha256 $gxwSha --allow-root $gxwRoot --device M100
```

`inventory`는 명령 본체를 해독하지 않고 검출된 프로그램 목록을 출력합니다. `inspect`는 지원되는 관측과 미해결 항목을, `query`는 지정한 디바이스의 관측 참조를 출력합니다. 조회 결과가 비어 있어도 프로젝트 전체에서 해당 디바이스를 사용하지 않는다는 뜻은 아닙니다.

### 텍스트와 CSV 내보내기

```powershell
.\.venv-gxw\Scripts\gxw-inspect.exe .\sample.gxw --text-encoding cp949
.\.venv-gxw\Scripts\gxw-inspect.exe .\sample.gxw --csv .\csv-output --text-encoding cp949
```

텍스트 예제는 한글 Statement/Note에 CP949를 선택하며 기본값인 CP1252를 쓰려면 해당 옵션을 생략합니다. 부모 디렉터리가 있는 새 출력 디렉터리를 사용하고 다시 내보낼 때에도 새 이름을 지정합니다. CSV 디렉터리 모드는 검출된 POU마다 파일 하나와 `COMMENT.csv`를 작성합니다. 출력에 프로젝트 이름과 주석이 포함될 수 있으므로 공유 전에 내용을 확인합니다.

### GXW CLI 명령

| 명령 | 용도 |
| --- | --- |
| `gxw-analyze` | 입력 해시를 고정한 프로그램 목록, 분석, 조회, 비교와 디바이스 참조 스냅샷 |
| `gxw-inspect` | 텍스트와 CSV 출력 |
| `gxw-reference-ir` | 디바이스 참조 JSON 출력 |
| `gxw-read-service` | 운영자가 등록한 프로젝트의 로컬 읽기 |
| `gxw-read-mcp` | 같은 등록 프로젝트를 stdio MCP로 읽기 |

서비스와 MCP는 Windows와 사용 권한이 있는 합성 프로젝트 등록이 필요하며 임의 파일에 접근하는 서버가 아닙니다. 설정 JSON의 로컬 사본에 입력의 절대 path/root, SHA-256과 접근 범위를 지정합니다. 별도 감사 디렉터리를 준비하고 alias key 자리표시자를 비공개 무작위 키로 바꾸며 입력과 감사 디렉터리는 분리합니다. 완성한 설정의 SHA-256을 구한 뒤 설치 환경에서 `gxw-read-mcp --config <config.json> --config-sha256 <digest>`로 시작합니다. 키를 공유하거나 등록 범위를 넘어서는 접근을 허용하지 않습니다. [GXW 설정과 MCP 사용법](docs/gxw-read-v1.md), [설정 예제](examples/gxw-read-v1-config.json)와 [변경 사항](docs/releases/gxw-0.2.0a2.md)을 참고하세요. 설정 예제의 자리표시자는 실제 환경에 맞게 바꿔야 합니다.

## FX5/iQ-R 판독기 빌드와 실행

Git과 Python 3.12 이상이 필요합니다. 깨끗한 clone에서 별도 빌드 환경을 만듭니다. 가상환경과 빌드 출력에는 새 경로를 사용하고 빌드 디렉터리는 checkout 밖에 둡니다. 빌드 의존성 설치에는 네트워크가 필요합니다.

```powershell
git clone https://github.com/plcmanjp/gx-project-toolkit.git gx-project-toolkit
Set-Location gx-project-toolkit
python -m venv ..\gx3-build-env
$gx3Python = (Resolve-Path '..\gx3-build-env\Scripts\python.exe').Path
& $gx3Python -m pip install --require-hashes -r requirements-build.txt
& $gx3Python -X utf8 tools/build_artifacts.py --output ..\gx3-build
$fx5Wheel = Get-Item '..\gx3-build\artifacts\packages\gx3-fx5\*.whl'
$rWheel = Get-Item '..\gx3-build\artifacts\packages\gx3-r\*.whl'
& $gx3Python -m pip install --no-deps $fx5Wheel.FullName $rWheel.FullName
```

FX5/R wheel은 추가 런타임 의존성을 선언하지 않으므로 이 절차에서는 `--no-deps`를 사용합니다. 프로젝트 입력은 소스 checkout 밖에 둡니다. 아래 절대 경로를 지원 프로필에 맞는 사용 권한 보유 사본으로 바꿔 분석합니다.

```powershell
..\gx3-build-env\Scripts\gx3-fx5-inspect.exe C:\gx-projects\sample-fx5.gx3 --summary
..\gx3-build-env\Scripts\gx3-r-inspect.exe C:\gx-projects\sample-r.gx3 --summary
```

전체 JSON과 출력 디렉터리 옵션은 각 명령의 `--help`를 확인하세요. 출력 내용과 완성도는 선택한 형식과 프로필에 따라 달라집니다.

## 결과 해석

- 읽기는 부분 지원입니다. coverage, 미인식 명령과 미해결 항목을 확인해야 하며 실행 성공이 모든 POU와 설정의 해독을 뜻하지는 않습니다.
- GXW 구조화 분석 프로필(Read-V1)은 직접 Boolean과 `MOV`/`DMOV`의 제한된 형식을 다루며 `PARTIAL`, `complete_search: false`를 유지합니다. 별도 텍스트/CSV 판독기는 자체 인식 형식과 진단을 제공하며 그 출력이 구조화 분석의 지원 계약을 확대하지는 않습니다.
- 디바이스 참조 스냅샷은 프로그램의 참조를 뜻하며 실제 PLC 메모리나 운전 상태가 아닙니다.
- 파서 결과는 CPU 주소 적법성, GX 재빌드 성공, 대상 변환 또는 현장 사용을 검증하지 않습니다. 설비에 적용하기 전에 해당 엔지니어링 소프트웨어로 프로젝트를 검토해야 합니다.

Mitsubishi Electric과 제휴하거나 승인을 받은 도구가 아닙니다.

## 문서와 지원

- [호환성 표](docs/compatibility-matrix-ko.md)
- [GXW 설정과 MCP 사용법](docs/gxw-read-v1.md)
- [FX5 명령 상세(영문)](docs/fx5-mil-pointer-control.md)와 [위치결정 피연산자(영문)](docs/fx5-mil-positioning-operands.md)
- [iQ-R 주석과 라벨의 읽기 한계(영문)](docs/r-object-reading.md)
- [안전 경계](docs/safety-boundaries-ko.md)
- [버그 제보](https://github.com/plcmanjp/gx-project-toolkit/issues)와 [기여 안내](CONTRIBUTING-ko.md)
- [보안 문제 보고](SECURITY-ko.md)

문제 제보에는 식별 정보를 지운 패키지 버전, 실행 명령과 오류 내용을 포함해 주세요. 고객 프로젝트, 공식 export와 기밀 자료는 첨부하지 않습니다.

## 라이선스

[Apache-2.0](LICENSE). [NOTICE](NOTICE), [의존성 고지](THIRD_PARTY_NOTICES-ko.md)와 [사용 및 재배포 정책](docs/usage-rights-policy-ko.md)을 참고하세요.
