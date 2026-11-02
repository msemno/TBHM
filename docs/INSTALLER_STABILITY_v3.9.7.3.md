# TBHM v3.9.7.3 Installer Stability

## Root cause

The previous full installer combined independent application stacks—Semgrep, Checkov, capa/FLOSS, angr, pyATS, data-analysis libraries and others—inside one Python 3.13 user site. Their dependency constraints are not one coherent application environment. Pip therefore replaced shared versions of packages such as Pydantic, Protobuf, NetworkX and ruamel.yaml, producing conflicts even when individual installation commands returned success.

## New environment model

- Core TBHM uses only `requirements.txt`.
- Every optional pip or pipx catalog entry uses its own virtual environment: `${TBHM_TOOL_HOME:-~/.local/share/tbhm-tools}/venvs/<tool-id>`.
- CLI launchers are exposed through `~/.local/bin`.
- Libraries needed by TBHM use explicit isolated bridges rather than being imported accidentally from the user site.
- npm uses a user prefix. Ruby and Composer user bin paths are linked into the same local bin.
- Apt installation is preflighted and classified before execution.

## Full installation

```bash
set -o pipefail
INSTALL_CODE_SECURITY=1 \
INSTALL_REVERSE_TOOLING=1 \
INSTALL_ANGR=1 \
INSTALL_OLLAMA=1 \
INSTALL_AI=1 \
AI_NO_PULL=1 \
INSTALL_PLAYWRIGHT=1 \
INSTALL_ALL_SAFE_EXTENDED=1 \
./install.sh 2>&1 | tee install-full-v3.9.7.3.log
```

Expected limitations are not fatal: an unsupported interpreter, absent repository package, archived upstream project or optional API key is reported as skipped/unavailable rather than a generic failure.

## Diagnose an existing host

```bash
python3 scripts/installer_doctor.py
python3 scripts/installer_doctor.py --json > installer-doctor.json
python3 scripts/repair_legacy_python_environment.py
```

The cleanup utility is conservative. Its default is a plan. `--apply` is permitted only for known top-level packages from the previous installer when the corresponding isolated replacement marker exists. Shared dependencies are never automatically downgraded or removed.

## Testing boundary

The release was tested with offline fixtures, mocked installer outcomes, syntax/configuration checks, CLI smoke tests and the complete TBHM integration matrix. A full live apt/npm/pip/cargo download replay was not performed in the build environment; network/repository availability remains host-dependent and is now represented truthfully.
