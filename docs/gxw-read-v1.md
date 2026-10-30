# GXW Read-V1 사용법

`gxw-parser-toolkit` **0.2.0a1**은 GXW의 제한된 읽기 관측을 제공하는 실험적 배포본이다. Python 3.12 이상을 사용한다. 등록 서비스와 MCP의 자원 격리는 Windows 환경을 요구한다. 이 문서의 예제는 사용 권한이 있는 합성 프로젝트만 대상으로 한다.

프로젝트 파일을 수정하거나 GX를 실행하지 않는다. JSON 결과, 선택한 출력 파일과 서비스 감사 로그는 로컬에 기록할 수 있다. 분석 성공은 전체 프로젝트 판독, 명령의 CPU 적법성, GX 검사 통과 또는 실제 설비 수락을 의미하지 않는다.

## 설치와 환경 분리

이전 `gxw-parser-toolkit`과 별도 읽기 전용 후보 배포물은 Python 모듈과 CLI 이름을 공유할 수 있다. 함께 설치하지 말고 새 가상 환경에 이 배포본만 설치한다. 기존 프로젝트의 환경과 소비 버전을 자동으로 바꾸지 않는다.

아래 PowerShell 예제는 제공받은 wheel을 `wheelhouse`에 둔 경우다. 예제 이름의 파일이 실제로 있어야 한다.

```powershell
$env:PYTHONUTF8 = '1'
py -3.12 -m venv .venv-gxw-read-v1
$gxwPython = (Resolve-Path '.\.venv-gxw-read-v1\Scripts\python.exe').Path
& $gxwPython -m pip install '.\wheelhouse\gxw_parser_toolkit-0.2.0a1-py3-none-any.whl[mcp]'
```

`[mcp]`는 선택 MCP 의존성을 함께 설치한다. 로컬 분석만 필요하면 wheel 경로 끝의 `[mcp]`를 생략할 수 있다. 다음의 읽기 진입점 5개를 제공한다.

| CLI | Python 모듈 | 용도 |
|---|---|---|
| `gxw-inspect` | `gxw_ladder_reader` | 기존 텍스트 관측과 선택 CSV 출력 |
| `gxw-analyze` | `gxw_project_analysis` | 고정 SHA 입력의 inventory, 분석, 조회, 비교와 Read-V1 출력 |
| `gxw-reference-ir` | `gxw_reference_ir` | 관측 디바이스 참조를 JSON 파일로 출력 |
| `gxw-read-service` | `gxw_analysis_service` | 운영자가 등록한 프로젝트 ID로 로컬 읽기 요청 |
| `gxw-read-mcp` | `gxw_analysis_mcp` | 같은 등록 설정을 사용하는 stdio MCP |

입력 SHA와 허용 디렉터리 검사가 필요한 경우에는 `gxw-analyze` 또는 등록 서비스를 사용한다. 기존 `gxw-inspect`와 `gxw-reference-ir`에 등록 서비스의 권한 검사가 적용된다고 가정하지 않는다.

## 관측 범위와 결과 해석

Read-V1의 출력 profile은 `q06udv-simple-ladder-read-v1`이다. 다음 12개 명령 형식의 유한 관측 계약을 제공한다.

| 형식 | 피연산자 계약 |
|---|---|
| `END` | 피연산자 없음 |
| `LD`, `LDI`, `AND`, `ANI`, `OR`, `ORI`, `OUT`, `SET`, `RST` | 직접 비트 디바이스 1개 |
| `MOV` | 직접 워드 또는 16비트 K/H 상수, 직접 워드 목적지 |
| `DMOV` | 직접 워드 또는 32비트 K/H 상수, 직접 워드 목적지 |

직접 비트 family는 `B/C/F/L/M/SB/SM/ST/T/X/Y`, 직접 워드 family는 `D/FD/R/SD/SW/W/Z/ZR`다. 이 계약의 직접 형식에서는 자릿수 묶음, 인덱스, 간접 지정, 모듈 지정과 워드 비트 수식자를 제외한다. family가 목록에 있다는 사실만으로 특정 CPU의 모든 주소, 명령 또는 접근 폭을 승인하지 않는다.

입력에서 발견한 `Q06UDV` 또는 `Q06UDVCPU` 문자열은 profile 진입 조건으로만 사용한다. CPU identity를 인증하지 않는다. 문자열이 없거나 다른 후보와 섞이면 `PROFILE_LITERAL_MISSING_OR_AMBIGUOUS`로 거부될 수 있다. 등록 서비스의 profile 표기는 `q06udv-simple-ladder-observed`이며, 응답의 `profile_state`는 `DECLARED_NOT_AUTHENTICATED`다.

`inventory`는 프로그램 목록과 크기 등의 구조 관측이다. 명령 행과 파라미터를 해독하지 않으므로 목록을 얻었다고 전체 POU의 의미를 읽었다고 볼 수 없다. `inspect`는 지원되는 행, 텍스트와 참조 등을 관측한다. 등록 서비스의 `inspect` 응답은 로컬 `inspect` JSON 전체를 그대로 공개하지 않는다.

Read-V1과 디바이스 snapshot은 `state: PARTIAL`, `complete_search: false`를 유지한다. 다음 필드도 함께 확인한다.

- `unknown_instructions`: 관측한 미인식 명령과 개수. `NOT_ANALYZED`나 `null`은 0과 다르다.
- `unsupported_in_v1`: Read-V1 계약 밖의 형식.
- `unrecognized_members`, `unresolved_edges`: 해독하거나 연결하지 못한 항목.
- `reference_state`, 접근 역할과 coverage 상태: 관측 여부와 정적/동적/미해결 범위.

빈 조회 결과는 미사용의 전수 증명이 아니다. POU 이름과 순서는 실행 일정이나 역할을 인증하지 않는다. 주석의 일반 소유권과 Note 하위 유형도 확정하지 않는다. 비교 결과는 `binary`, `structure`, `supported_observations`를 구분하며 전체 의미는 `overall_semantic: UNKNOWN`으로 남는다.

## SHA를 고정한 로컬 CLI

`C:\gxw-read-demo\inputs\demo-a.gxw`는 사용자가 별도로 준비한 합성 입력을 뜻한다. 이 문서는 실행 가능한 GXW를 제공하지 않는다. 아래 경로를 실제 권한이 있는 입력으로 바꾸고 파일이 변경되지 않는 상태에서 SHA를 구한다.

```powershell
$gxwRoot = 'C:\gxw-read-demo\inputs'
$gxwSource = Join-Path $gxwRoot 'demo-a.gxw'
$gxwSourceSha = (Get-FileHash -LiteralPath $gxwSource -Algorithm SHA256).Hash.ToLowerInvariant()

& $gxwPython -I -B -m gxw_project_analysis inventory $gxwSource --sha256 $gxwSourceSha --allow-root $gxwRoot
& $gxwPython -I -B -m gxw_project_analysis inspect $gxwSource --sha256 $gxwSourceSha --allow-root $gxwRoot
& $gxwPython -I -B -m gxw_project_analysis read-v1 $gxwSource --sha256 $gxwSourceSha --allow-root $gxwRoot
& $gxwPython -I -B -m gxw_project_analysis snapshot $gxwSource --sha256 $gxwSourceSha --allow-root $gxwRoot
& $gxwPython -I -B -m gxw_project_analysis query $gxwSource --sha256 $gxwSourceSha --allow-root $gxwRoot --device M0
```

`snapshot`의 schema는 `gx-project-toolkit.device-references/1`이다. 프로그램에 관측된 디바이스 참조를 모으는 출력이며 PLC 메모리나 운전 상태의 snapshot이 아니다. 대응 JSON Schema의 파일명은 `device-references-v1.schema.json`이다.

두 입력을 비교할 때에는 양쪽 SHA가 필요하고, 두 파일 모두 같은 `--allow-root` 아래에 있어야 한다.

```powershell
$gxwRight = Join-Path $gxwRoot 'demo-b.gxw'
$gxwRightSha = (Get-FileHash -LiteralPath $gxwRight -Algorithm SHA256).Hash.ToLowerInvariant()
& $gxwPython -I -B -m gxw_project_analysis compare $gxwSource --sha256 $gxwSourceSha --allow-root $gxwRoot --right $gxwRight --right-sha256 $gxwRightSha
```

로컬 CLI는 기본적으로 이름, 경로와 본문 텍스트를 가린다. 운영자가 로컬 출력의 공개 범위를 판단한 뒤 `--include-text`를 지정하면 관측된 이름과 텍스트를 포함할 수 있다. 기본 출력도 source digest, 디바이스 주소와 명령 등 일부 정보를 담으므로 완전한 익명화 출력으로 취급하지 않는다. 이 옵션은 MCP 공개 권한과 별개다.

## 등록 설정

[예제 설정](../examples/gxw-read-v1-config.json)은 실제 설정과 같은 JSON 구조지만 그대로 실행할 수 없다. `demo-a`는 합성 식별자다. 예제 경로는 준비된 입력을 가리키지 않으며, 64자리 0은 실제 digest나 비밀키가 아닌 자리표시자다. JSON 주석이나 임의 키를 추가하지 않는다.

운영자가 다음을 준비한다.

1. 소유하거나 사용 승인을 받은 합성 GXW와 입력 전용 디렉터리.
2. 입력 디렉터리와 서로 포함 관계가 없는 별도 감사 디렉터리. 두 디렉터리는 미리 존재해야 한다.
3. 프로젝트별 절대 `path`, 절대 `root`, 현재 파일의 소문자 SHA-256. 파일은 `root` 하위의 일반 파일이어야 한다.
4. 64자리 소문자 16진수 `alias_key`. 예제의 0 대신 운영자가 생성한 무작위 키를 사용하고 비공개로 보관한다.
5. `profile: q06udv-simple-ladder-observed`, `authority: authorized-synthetic`. 현재 등록 계약이 허용하는 정확한 값이다. 이 표기는 파일 자체의 진위나 CPU를 인증하지 않는다.

프로젝트 ID는 소문자로 시작하는 영문 소문자, 숫자, `_`, `-`의 조합이며 최대 48자다. 프로젝트는 1~32개 등록할 수 있다. `limits`는 선택 사항이다.

| 설정 | 기본값 | 허용 범위 |
|---|---:|---|
| `timeout_seconds` | 10 | 0.1~60초 |
| `memory_bytes` | 268435456 | 33554432~1073741824 bytes |
| `page_size` | 100 | 정수 1~200 |

편집을 마친 설정은 예를 들어 `C:\gxw-read-demo\config.json`에 저장한다. digest는 JSON의 원시 파일 bytes에 적용하므로 공백이나 줄바꿈만 바꿔도 다시 계산해야 한다.

```powershell
$gxwConfig = 'C:\gxw-read-demo\config.json'
$gxwConfigSha = (Get-FileHash -LiteralPath $gxwConfig -Algorithm SHA256).Hash.ToLowerInvariant()

& $gxwPython -I -B -m gxw_analysis_service --config $gxwConfig --config-sha256 $gxwConfigSha inventory demo-a
& $gxwPython -I -B -m gxw_analysis_service --config $gxwConfig --config-sha256 $gxwConfigSha inspect demo-a --offset 0
& $gxwPython -I -B -m gxw_analysis_service --config $gxwConfig --config-sha256 $gxwConfigSha query demo-a --device M0 --offset 0
```

`compare demo-a --right-id demo-b`를 쓰려면 `demo-b`도 동일한 설정에 등록해야 한다. 원본을 교체했다면 기존 digest를 자동 갱신하지 말고 등록 대상과 권한을 다시 확인한다.

## MCP 기본 공개와 상세 grant

예제의 `disclosure: summary-only`는 개수와 가명 locator 중심의 결과를 제공한다. `detail_fields`를 추가하면 이 모드에서는 설정을 거부한다. 모델이나 도구 호출자는 파일 경로, SHA, 공개 모드, `include_text` 또는 임의 정책을 인자로 넘겨 권한을 높일 수 없다.

상세가 필요한 운영자는 설정을 직접 검토하여 `disclosure`를 `authorized-detail`로 바꾸고 **등록된 각 프로젝트**에 필요한 `detail_fields`만 명시한다. 예를 들어 POU 이름과 직접 참조만 허용할 때의 프로젝트별 추가 값은 다음과 같다.

```json
"detail_fields": ["pou_names", "references"]
```

이는 설정 전체가 아닌 프로젝트 객체에 넣는 속성 예시다. 허용 값은 아래 네 가지이며, 비어 있거나 중복된 목록과 미등록 값은 거부한다.

| grant | 공개할 수 있는 관측 |
|---|---|
| `pou_names` | 관측 POU 이름 |
| `device_comments` | 허용된 디바이스 주석 관측 |
| `text_records` | 연결 가능한 Statement/Note 관측 |
| `references` | 직접 디바이스 참조와 접근 역할 |

상세는 `inspect`와 `query`에 한해 투영되며 `query`는 관련 디바이스 주석과 참조만 적용한다. 이름 grant가 없으면 POU 표기는 가명으로 유지된다. grant를 주어도 미해결 연결이나 소유권을 확정하지 않으며 모든 원문을 반환하지 않는다. 설정 변경 후 digest를 다시 고정하고 서버를 다시 시작한다. `--include-text`는 MCP 실행 옵션이 아니다.

stdio MCP 서버의 실제 실행 문법은 다음과 같다. MCP 클라이언트가 이 명령을 자식 프로세스로 시작하고 표준 입출력을 연결하도록 설정한다.

```powershell
& $gxwPython -I -B -m gxw_analysis_mcp --config $gxwConfig --config-sha256 $gxwConfigSha
```

MCP 도구는 네 개다. `offset`은 공통 선택 인자이며 기본값은 0이다.

| 도구 이름 | 필수 인자 |
|---|---|
| `inventory` | `project_id` |
| `inspect` | `project_id` |
| `reference_query` | `project_id`, `device` |
| `compare` | `project_id`, `right_id` |

호출 인자 예시는 `{"project_id":"demo-a","device":"M0","offset":0}`이다. `reference_query`는 `M0` 같은 직접 주소를 요구하며 인덱스, 간접 지정과 자릿수 묶음을 조회 대상으로 받지 않는다. `read-v1`과 `snapshot`은 로컬 분석 CLI의 operation이며 별도 MCP 도구 이름이 아니다.

`page.next_offset`이 있으면 그 값으로 다음 페이지를 요청한다. 상세 응답에는 별도 `detail.page`도 있으므로 각각 확인한다. 페이지를 모두 받았다는 사실은 전체 프로젝트의 의미 해독 완료를 뜻하지 않는다. 상세의 `expected_total`은 `null`, `complete`는 `false`로 유지된다.

## 한도와 거부 결과

로컬 분석의 주요 기본 한도는 입력 16 MiB, 행 20000개, 응답 8 MiB다. 내부 항목의 수와 크기에도 별도 한도를 적용한다. inventory도 입력과 구조 한도를 적용한다. 파일 변경, SHA 불일치, 허용 root 이탈, 링크 및 지원하지 않는 구조는 거부한다. 한도에 걸린 입력을 inventory 성공이나 잘린 성공 결과로 대신 승인하지 않는다.

등록 서비스와 MCP는 요청을 한 번에 하나 처리하며, 서비스 응답 한도는 64 KiB, MCP 입력 frame 한도는 16 KiB다. 시간과 메모리 제한 또는 자원 격리 설정 실패를 오류로 반환한다. 원시 분석 API 자체는 OS 시간/메모리 격리를 제공하지 않는다.

| 코드 예 | 의미 |
|---|---|
| `SHA256_MISMATCH` | 등록하거나 전달한 digest와 입력 bytes 불일치 |
| `PATH_OUTSIDE_ALLOW_ROOT` | 허용 root 범위 밖의 입력 |
| `ROW_LIMIT`, `CFB_STREAM_BUDGET`, `RESPONSE_LIMIT` | 분석 한도 초과 |
| `DETAIL_GRANT_REQUIRED`, `DETAIL_GRANT_REJECTED` | 상세 공개 설정 불충족 |
| `RESOURCE_ISOLATION_UNAVAILABLE`, `TIMEOUT`, `MEMORY_LIMIT` | 격리 또는 실행 자원 조건 불충족 |
| `WORKER_RESPONSE_LIMIT`, `BUSY` | 서비스 응답 한도 또는 동시 요청 거부 |
| `AUDIT_FAILED` | 감사 기록 실패로 요청 중단 |

MCP 입력 frame이 한도를 넘거나 형식이 잘못되면 연결이 종료될 수 있다. 감사 로그에는 설정 digest, source digest와 요청 상태 등이 남을 수 있다. 응답의 가명 처리와 별개로 운영자가 감사 디렉터리의 접근을 관리해야 한다. 거부는 입력의 손상 원인 확정이나 수정 권한을 뜻하지 않는다. 이 배포본은 전체 POU, 전체 GXW 형식, 실제 PLC 동작 또는 현장 안전을 승인하지 않는다.
