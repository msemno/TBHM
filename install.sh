#!/usr/bin/env bash
# TBHM 4.2.7 core installer. No sudo, global pip changes or tool downloads.
set -Eeuo pipefail
TBHM_RELEASE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TBHM_VENV="$TBHM_RELEASE_ROOT/.venv"
TBHM_INSTALL_MODE=offline
TBHM_PYTHON="${PYTHON_BIN:-python3}"
if command -v python3.12 >/dev/null 2>&1; then TBHM_PYTHON="${PYTHON_BIN:-python3.12}"; fi
while (($#)); do
  case "$1" in
    --offline) TBHM_INSTALL_MODE=offline; shift ;;
    --online) TBHM_INSTALL_MODE=online; shift ;;
    --venv) TBHM_VENV="${2:?--venv requires a path}"; shift 2 ;;
    --python) TBHM_PYTHON="${2:?--python requires an interpreter}"; shift 2 ;;
    -h|--help) printf '%s\n' 'TBHM 4.2.7: bash install.sh [--offline|--online] [--python python3.12] [--venv PATH]' 'Default: install only the pinned core from bundled wheels into .venv.'; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
"$TBHM_PYTHON" - "$TBHM_RELEASE_ROOT" <<'PY'
import platform, sys
from pathlib import Path
if sys.version_info[:2] != (3, 12):
    raise SystemExit('TBHM 4.2.7 packaged runtime requires Python 3.12. Use --python /path/to/python3.12.')
if sys.platform != 'linux' or platform.machine() not in {'x86_64', 'amd64'}:
    raise SystemExit('This offline distribution targets Linux x86-64. Other platforms are not validated.')
root = Path(sys.argv[1]); sys.path.insert(0, str(root))
from core.package_verifier import verify_tree
result = verify_tree(root, compile_python=False, require_manifest=True)
if not result['passed']:
    raise SystemExit('Package integrity failed: ' + '; '.join(result['issues'][:8]))
print('Package integrity verified.')
PY
"$TBHM_PYTHON" -m venv "$TBHM_VENV"
TBHM_PIP_ARGS=(--disable-pip-version-check --require-hashes -r "$TBHM_RELEASE_ROOT/requirements.lock")
if [[ "$TBHM_INSTALL_MODE" == offline ]]; then TBHM_PIP_ARGS+=(--no-index --find-links "$TBHM_RELEASE_ROOT/vendor/wheels"); fi
"$TBHM_VENV/bin/python" -m pip install "${TBHM_PIP_ARGS[@]}"
"$TBHM_VENV/bin/python" -m pip check
"$TBHM_VENV/bin/python" "$TBHM_RELEASE_ROOT/tbhm.py" --version
printf '\nInstalled TBHM 4.2.7 in %s\nRun: %s/tbhm --help\n' "$TBHM_VENV" "$TBHM_RELEASE_ROOT"
