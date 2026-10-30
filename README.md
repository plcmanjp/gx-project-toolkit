# GX RE Toolkit

GXW 읽기 전용 프리뷰 `gxw-parser-toolkit 0.2.0a1`의 [설치와 사용법](docs/gxw-read-v1.md), [변경 사항](docs/releases/gxw-0.2.0a1.md)을 확인하세요. 이 프리뷰의 wheel/sdist에는 읽기 모듈과 읽기 CLI/MCP만 포함됩니다. 아래 기존 작성 기능 설명은 이전 `0.1.0`에 해당하며 이번 프리뷰의 지원 범위가 아닙니다. 새 가상환경에서 개별 설치하고 기존 통합 환경이나 소비 pin을 자동 갱신하지 마세요.

[English](README.md) | [한국어](README-ko.md)

An independent research toolkit for offline analysis of the explicitly supported
Mitsubishi project formats. It is not affiliated with or endorsed by Mitsubishi
Electric. Successful analysis does not establish a successful GX rebuild,
agreement with official exports, approval for PLC use, or field safety.
The source is published for offline research, not approved for field deployment.

## Packages

| Distribution | Version | Purpose |
| --- | --- | --- |
| gx3-fx5-parser-toolkit | 0.4.0 | GX3 FX5 structure and Neutral IR analysis |
| gx3-r-parser-toolkit | 0.2.0 | Read-only analysis of MELSEC iQ-R family GX Works3 projects |
| gxw-parser-toolkit | 0.2.0a1 | Q06UDV 제한 읽기와 CLI/MCP 프리뷰 |
| gx-re-lab | 0.1.0 | Bounded comparison, census, planning, and reduction research tools |

Python 3.12 or later is required. Full writing functionality uses Windows and
pywin32. See the [compatibility matrix](docs/compatibility-matrix.md) for CPU
coverage and limitations. Private originals, customer data, official exports,
and vendor materials are not included. Default tests and runtime operations do
not launch GX software or connect to a PLC.

## Project direction

The `gx3-r-parser-toolkit` is intended to become a general-purpose, read-only
analysis toolkit for MELSEC iQ-R family GX Works3 projects. R04CPU is the current
implementation and validation starting point, not the project's long-term scope.

The current explicit supported profile remains R04CPU Ladder with the
`R04/4097` Unit/UnitId pair. Other explicit CPU pairs are reported as
`UNSUPPORTED`; missing or ambiguous identity evidence is reported as
`AMBIGUOUS`. Extending the iQ-R scope requires evidence for each added CPU and
project format, explicit profile handling, and regression validation. This
direction does not claim that other iQ-R CPUs are supported today or authorize
PLC operation or field deployment. See the
[compatibility matrix](docs/compatibility-matrix.md) for current boundaries.

## GXW 프리뷰 빌드와 설치

현재 `gxw-parser-toolkit 0.2.0a1`은 아래 개별 빌드와 독립 설치 검증을 사용합니다. 기존 `lab`의 GXW `0.1.0` 소비 pin과 다른 패키지 버전은 보존합니다. 새 GXW wheel과 이전 통합 환경을 함께 설치하거나 기존 `verify_install.py` 기본 profile로 검사하지 않습니다. FX5/R의 독립 설치 profile은 기존 계약을 유지합니다.

커밋한 깨끗한 독립 checkout에서 Windows CPython 3.13으로 실행합니다. 출력 경로는 checkout 밖의 새 경로여야 합니다. 아래 의존성 다운로드에는 네트워크가 필요하고 실제 검증기는 준비된 wheelhouse만 사용합니다.

```powershell
$env:PYTHONUTF8 = '1'
py -3.13 -m venv C:\Temp\gxw-build-env
$gxwPython = 'C:\Temp\gxw-build-env\Scripts\python.exe'
& $gxwPython -m pip install --require-hashes -r requirements-gxw-preview.txt
& $gxwPython -m pip download --require-hashes --only-binary=:all: --dest C:\Temp\gxw-wheels -r requirements-gxw-preview.txt
& $gxwPython -I -B tools/build_gxw_preview.py --source $PWD --output C:\Temp\gxw-build
& $gxwPython -I -B tools/verify_gxw_preview.py --manifest C:\Temp\gxw-build\build-manifest.json --wheelhouse C:\Temp\gxw-wheels --output C:\Temp\gxw-verification
```

두 산출물과 공개 commit/tree의 신원은 `build-manifest.json`에 기록됩니다. 검증기는 새 가상환경에서 설치 경로/모듈 해시, 읽기 진입점, 합성 시험과 MCP stdio를 검사합니다. 편집 가능 설치나 소스 경로 주입은 배포 설치 검증 근거가 아닙니다. [사용법과 제한](docs/gxw-read-v1.md)을 확인하세요.

## Usage

The FX5 read-only decoder's exact MIL `CALL`, pointer declaration, `FEND` and
`RET` syntax and unsupported variants are described in
[pointer-control syntax](docs/fx5-mil-pointer-control.md). Syntax coverage is not
GX, simulator, consumer or field acceptance.

The GXW Python reader accepts `text_encoding="cp949"` or `"cp1252"` for
source Statement and Note frames. The default is strict CP1252. The optional
`"auto"` policy prefers reversible CP949 and then reversible CP1252; it is a
Korean Windows policy, not proof of a project's original code page. Decoding
never substitutes replacement characters. Counted COMMENT text remains
UTF-16. `typed_note_records(..., framed_types=True)` exposes the byte-length
Note subtype relation, raw bytes and instruction attachment for independent
binding checks. These options do not establish an official GX import result.

Both `gxw-inspect` and `gxw-reference-ir` accept
`--text-encoding {cp1252,cp949,auto}`, with `cp1252` as the compatibility default.
The selected policy applies to text, stdout CSV, directory CSV, typed Note
binding and Reference IR construction. Unknown options and invalid values are
rejected before input reading. For example, use
`gxw-inspect project.gxw --csv new-directory --text-encoding cp949` or
`gxw-reference-ir project.gxw --output new.json --text-encoding cp949`.
The Python APIs retain their `text_encoding` keyword. Note subtype options remain
Python-only; request the extended view with
`typed_note_records(..., text_encoding="cp949", framed_types=True)`.

`typed_statement_records(..., text_encoding="auto")` keeps the exact body,
raw storage byte, In PLC/Peripheral type and stored step width separate from
the compatibility CSV marker. Literal leading stars remain part of the body.
Unknown types or unmatched source rows refuse typed promotion. FX5 Statement
provenance adds `statement_raw_st` and an exact UTF-8 body digest to the existing
relation evidence; the Neutral IR schema and compatibility text stay unchanged.
Decimal F device-comment keys are decoded under the existing non-extended,
non-indexed key restrictions. These source-format observations do not establish
target import, runtime device behavior or field acceptance.

Reference IR `COMPLETE` describes decoded syntax and classified operand access;
it does not establish a complete physical address range or official validation.
Unknown or malformed instructions prevent `COMPLETE` even without operands.
Reader findings are retained in additive `diagnostics`, with an additive
`coverage.unknown_instructions` count; existing fields, state values and schema
version remain unchanged. Recognized END/NOP and decoded dynamic addresses retain
their existing behavior. Statement/Note text is decoded but omitted from the
instruction-reference projection. The bounded source digest retains carrier
header bytes and the complete first END trailer outside balanced frames.

The examples below use the virtual environment from the build example. If you
installed elsewhere, replace the environment path with your installation path.

```powershell
C:\Temp\gx-build-env\Scripts\gx3-fx5-inspect.exe --help
C:\Temp\gx-build-env\Scripts\gx3-r-inspect.exe --help
C:\Temp\gx-build-env\Scripts\gxw-reference-ir.exe --help
C:\Temp\gx-build-env\Scripts\gxw-write.exe --help
C:\Temp\gx-build-env\Scripts\gxw-encode.exe --help
C:\Temp\gx-build-env\Scripts\python.exe -m gx_re_lab.lab --help
C:\Temp\gx-build-env\Scripts\python.exe -m gx_re_lab.census --help
C:\Temp\gx-build-env\Scripts\python.exe -m gx_re_lab.planner --help
```

`gx3-r-inspect --summary` emits only the derived `FULL`, `PARTIAL`, or `FATAL`
status, the R profile support decision, coverage totals, and a finding count. It
does not emit project names, records, operands, comments, labels, archive paths,
or other project strings. This is not a guarantee of complete anonymization;
review output before sharing. Normal output contains the complete R analysis.
It can be combined with `--output`: stdout remains the summary while the new
directory receives the complete artifact.

The Lab module CLIs are `explorer_diff`, `reference_query`, `census`,
`r04_census`, `gxw_census`, `planner`, `coverage_ledger`, `external_compare`,
`final_scope`, `lab`, `experiment`, `relation_audit`, `campaign_coverage`, and
`corpus_census`. See [corpus census](docs/corpus-census.md) for bounded,
pinned GX3-FX5/GXW-Q inventories and cross-project container-key observations.
Without an input, `gxw-inspect` and `python -m gxw_pou_devmap` display usage and
exit with code 1. Give writing tools only disposable input copies and new output
paths, never originals. Atomic protection against a hostile filesystem is not
guaranteed across all input and output operations.

`gxw-inspect project.gxw` prints every POU body returned by `collect_pous`,
together with the nonempty device-comment map. CSV directory mode writes one
file per detected POU plus `COMMENT.csv`. Without an output directory, `--csv`
selects `MAIN` when present, otherwise the first detected POU in name-sorted
order. Python callers can enumerate `collect_pous(streams)` rather than assume
a `MAIN` POU or a fixed stream number.

`gxw-inspect project.gxw --csv new-directory` requires an existing parent and
an output directory that does not exist. It validates every POU CSV name,
renders POU and `COMMENT.csv` files in a temporary sibling directory, then
renames the complete candidate to the new destination. A failed render or
rename leaves the final path absent. An existing destination is never opened
for writing. Using `--csv` without a directory still writes the selected POU
to stdout. Directory publication requires Windows no-replace rename or Linux
`renameat2` with `RENAME_NOREPLACE`; other platforms fail closed.
`gxw-write --replace` rejects an empty OLD pattern before reading project data,
including when Python assertions are optimized away.

GXW single-command `--apply` without `--all` accepts only an equal-length, complete
03-family command with one unmodified operand frame, or a proven fixed-arity 05
dispatch/XFER command whose `(marker, A, opcode)` exactly matches the public encoder
allowlist. It resolves one
XML POU `.res`/`.Program.pou` pair and consumes every payload byte under its bounded
command, line-statement, and Note grammar. Line statements use the exact
`<L> 80 <ceil(L/2)> <printable text (L-4)> <L>` form; Notes require that same
length relation or the public raw subtype `01`. K/H and floating constant frames
also have their encoder-derived width limits. An empty second `.res` payload gives a
two-copy form; otherwise all three copies must be byte-identical. All `_hdb` OLD
hits must be the resolved slices, and the container-wide OLD count is an additional
fail-closed ambiguity check, not a claimed physical-sector mapping. Unsupported
grammar, metadata-free input, divergent copies, embedded OLD bytes, malformed
headers/trailers, or ambiguity exits 10 without a candidate. Dry-run and explicit
global `--all` replacement retain their existing semantics.
Writer, fill, and transpose validate a temporary candidate before publishing to
a new output path. Existing outputs are refused. Reader failure, exception, or
the 30-second validation timeout fails the operation without publishing it.
Explicit `--in-place` is for disposable copies only and refuses an existing
`.bak`; candidate validation precedes backup creation and input replacement.
`--in-place` and `--out` cannot be combined. Input hash checks detect changes
during preparation and before publication; they do not provide a filesystem lock.
Numeric checks reject frame overflow while preserving valid negative two's
complement encodings. Frame width is not a CPU device or operand support claim.

## Validation and publication boundaries

`tools/audit_public_tree.py` checks paths, file types, and selected sensitive
patterns in the working tree, files reachable from all local refs, and
distributions supplied with `--artifact`. It is not exhaustive secret detection
or independent legal review. Do not combine private comparison results and public
synthetic tests into a claim of field acceptance.

- [Validation methodology](docs/validation-methodology.md)
- [Safety boundaries](docs/safety-boundaries.md)
- [Reverse engineering and rights policy](docs/reverse-engineering-policy.md)
- [Dependency notices](THIRD_PARTY_NOTICES.md)
- [External research boundaries](THIRD_PARTY_RESEARCH.md)
- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Documentation languages

English is the default documentation language. Korean translations use the
`-ko.md` suffix and link back to their English originals. Keep both versions in
sync when changing meaning, commands, or safety boundaries. The English version
is authoritative if translations differ. LICENSE and NOTICE retain their
original legal text.

## Recovery

On another machine, restore this repository independently, then select the
reviewed commit required by the consumer before building. Do not substitute the
latest branch tip for an approved artifact pin.

```powershell
git clone https://github.com/plcmanjp/gx-project-toolkit.git C:\Work\gx-re-toolkit
git -C C:\Work\gx-re-toolkit rev-parse --show-toplevel
git -C C:\Work\gx-re-toolkit remote get-url origin
git -C C:\Work\gx-re-toolkit switch --detach <reviewed-commit>
```

This checkout uses its own Git database. Another repository does not
automatically back up these files or commits. Create a Git bundle with explicit
refs outside the working tree, restore it separately, and verify the commit/tree.
A local backup is not off-device disaster recovery. Do not recursively clean a
parent directory: that can delete the nested repository.
