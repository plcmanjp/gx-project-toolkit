# GX Project Toolkit

[English](README.md) | [한국어](README-ko.md)

Read and inspect supported Mitsubishi GX Works2 (`.gxw`) and GX Works3 (`.gx3`) project files offline. Extract program structure, supported ladder instructions, device references and available comments into text, CSV or JSON, depending on the format.

The current GXW release is the **[0.2.0a2 read-only preview](https://github.com/plcmanjp/gx-project-toolkit/releases/tag/gxw-v0.2.0a2)**. It also provides a local reading service and a stdio MCP interface. It does not edit project files, launch GX Works or connect to a PLC.

## Supported formats

| Input | Package and current source version | Scope |
| --- | --- | --- |
| GX Works2 `.gxw` | `gxw-parser-toolkit 0.2.0a2` | Q06UDV Simple/Ladder structured analysis of direct Boolean and MOV/DMOV forms; inventory, reference queries/comparison, CSV/JSON and local CLI/MCP |
| GX Works3 `.gx3`, FX5 | `gx3-fx5-parser-toolkit 0.4.1` | Supported FX5 project structure, ladder records and device-reference analysis |
| GX Works3 `.gx3`, iQ-R | `gx3-r-parser-toolkit 0.2.0` | R04CPU Ladder profile (`R04/4097`), program records, available comments/labels and device-reference output |

GXW has downloadable preview packages. FX5 and iQ-R packages are built from source as shown below. Support is limited to the profiles and forms listed in the [compatibility matrix](docs/compatibility-matrix.md); it does not cover every CPU, instruction, language or project setting.

## Start with the GXW preview

Use Python 3.12 or later. These commands target Windows PowerShell; check that `python --version` selects Python 3.12 or newer. If necessary, replace `python` with your installed version launcher, such as `py -3.13`. The registered GXW service and MCP interface require Windows.

Installation downloads runtime dependencies (`olefile` and, on Windows, `pywin32`); MCP adds `mcp`. Internet access or a prepared dependency wheelhouse is required for installation. Analysis itself runs offline. The example `.gxw` and `.gx3` files are not supplied; prepare permitted project copies separately.

1. Download `gxw_parser_toolkit-0.2.0a2-py3-none-any.whl` from the [release page](https://github.com/plcmanjp/gx-project-toolkit/releases/tag/gxw-v0.2.0a2) into a local `downloads` folder.
2. Create a new environment and install the downloaded wheel. Keep it separate from other GXW package versions.

```powershell
python -m venv .venv-gxw
$gxwPython = (Resolve-Path '.\.venv-gxw\Scripts\python.exe').Path
& $gxwPython -m pip install '.\downloads\gxw_parser_toolkit-0.2.0a2-py3-none-any.whl'
& $gxwPython -m gxw_project_analysis --help
```

For Windows MCP use, install the optional dependencies in the same environment. Current registration accepts authorized synthetic projects only. The detailed configuration guide is currently in Korean; an English setup outline is given below.

```powershell
& $gxwPython -m pip install '.\downloads\gxw_parser_toolkit-0.2.0a2-py3-none-any.whl[mcp]'
```

### Inspect a project

Replace `sample.gxw` with a local copy of a project you have permission to use. The SHA-256 argument binds the analysis to that exact file, and `--allow-root` limits the input directory. `gxw-analyze` is the CLI equivalent of `python -m gxw_project_analysis` used here.

```powershell
$gxwInput = (Resolve-Path '.\sample.gxw').Path
$gxwRoot = Split-Path -Parent $gxwInput
$gxwSha = (Get-FileHash -LiteralPath $gxwInput -Algorithm SHA256).Hash.ToLowerInvariant()

& $gxwPython -m gxw_project_analysis inventory $gxwInput --sha256 $gxwSha --allow-root $gxwRoot
& $gxwPython -m gxw_project_analysis inspect $gxwInput --sha256 $gxwSha --allow-root $gxwRoot
& $gxwPython -m gxw_project_analysis query $gxwInput --sha256 $gxwSha --allow-root $gxwRoot --device M100
```

`inventory` lists detected programs without decoding their instruction bodies. `inspect` returns supported observations and unresolved items. `query` finds observed references to the selected device. An empty result does not prove that a device is unused throughout the project.

### Export text or CSV

```powershell
.\.venv-gxw\Scripts\gxw-inspect.exe .\sample.gxw --text-encoding cp949
.\.venv-gxw\Scripts\gxw-inspect.exe .\sample.gxw --csv .\csv-output --text-encoding cp949
```

These text examples select CP949 for Korean Statement/Note text; omit that option for the CP1252 default. Use a new output directory whose parent already exists, and choose another new name when exporting again. CSV directory mode writes one file per detected POU and `COMMENT.csv`. Exported text can contain project names and comments, so review it before sharing.

### GXW CLI commands

| Command | Use |
| --- | --- |
| `gxw-analyze` | Inventory, inspect, query, compare and device-reference snapshots with a fixed input digest |
| `gxw-inspect` | Text and CSV output |
| `gxw-reference-ir` | Device-reference JSON output |
| `gxw-read-service` | Local reads of projects registered by an operator |
| `gxw-read-mcp` | The same registered reads over stdio MCP |

The service and MCP require Windows and authorized synthetic-project registrations; they are not an unrestricted file-access server. For each entry, configure the permitted absolute input path/root, its SHA-256 and access settings in a local copy of the example JSON. Prepare a separate audit directory, replace the placeholder alias key with a private random key, and keep the input and audit directories separate. Compute the final configuration SHA-256, then start `gxw-read-mcp --config <config.json> --config-sha256 <digest>` from the installed environment. Never share the key or enable access beyond the registered scope. See the [GXW setup and MCP guide (Korean)](docs/gxw-read-v1.md), [example configuration](examples/gxw-read-v1-config.json) and [release notes](docs/releases/gxw-0.2.0a2.md). The example configuration contains placeholders and must be adapted before use.

## Build and use the FX5/iQ-R readers

Git and Python 3.12 or newer are required. From a clean clone, create a separate build environment. Choose new paths for the environment and build output; the build directory must be outside the checkout. Installing build dependencies requires network access.

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

The FX5/R wheels declare no additional runtime dependencies, so `--no-deps` is intentional here. Keep project inputs outside the source checkout. Replace the absolute paths below with permitted copies matching the supported profiles:

```powershell
..\gx3-build-env\Scripts\gx3-fx5-inspect.exe C:\gx-projects\sample-fx5.gx3 --summary
..\gx3-build-env\Scripts\gx3-r-inspect.exe C:\gx-projects\sample-r.gx3 --summary
```

Use each command's `--help` for full JSON and output-directory options. Output content and completeness depend on the selected format and profile.

## Interpret results

- Reading is partial. Check coverage, unknown instructions and unresolved items; successful execution does not mean that every POU or setting was decoded.
- The GXW structured-analysis profile (Read-V1) covers a limited set of direct Boolean and `MOV`/`DMOV` forms. It retains `PARTIAL` and `complete_search: false`. The separate text/CSV reader has its own recognized forms and diagnostics; its output does not extend this structured-analysis contract.
- A device-reference snapshot describes program references, not live PLC memory or operating state.
- Parser results do not validate CPU address legality, a successful GX rebuild, target conversion or field use. Review projects in the appropriate engineering software before using them on equipment.

This is an independent toolkit, not affiliated with or endorsed by Mitsubishi Electric.

## Documentation and support

- [Compatibility matrix](docs/compatibility-matrix.md)
- [GXW setup and MCP guide (Korean)](docs/gxw-read-v1.md)
- [FX5 instruction details](docs/fx5-mil-pointer-control.md) and [positioning operands](docs/fx5-mil-positioning-operands.md)
- [iQ-R comment and label limitations](docs/r-object-reading.md)
- [Safety boundaries](docs/safety-boundaries.md)
- [Report a bug](https://github.com/plcmanjp/gx-project-toolkit/issues) or see [contribution guidance](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

When reporting a problem, include the package version, command and error text with identifying details removed. Do not attach customer projects, official exports or confidential data.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE), [dependency notices](THIRD_PARTY_NOTICES.md) and the [use and redistribution policy](docs/usage-rights-policy.md).
