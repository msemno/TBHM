#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v go >/dev/null 2>&1; then
  echo "Go is optional and was not found. Python executor remains available." >&2
  exit 0
fi
mkdir -p "$ROOT/bin"
(cd "$ROOT/tooling/go_executor" && go build -trimpath -ldflags='-s -w' -o "$ROOT/bin/tbhm-go-executor" .)
chmod 0755 "$ROOT/bin/tbhm-go-executor"
echo "$ROOT/bin/tbhm-go-executor"
