#!/usr/bin/env bash
# TBHM background runner
# Use this when you want to start a long scan and walk away.
# It survives:
#   - screen turning off / laptop lid closing
#   - SSH session disconnect
#   - terminal window close
#
# Usage:
#   ./run-bg.sh -d target.com -y --deep
#   ./run-bg.sh -l domains.txt -y --insane --bug-bounty-program "..."

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sleep inhibitor wrapper (best-effort)
INHIBIT=""
if [ "$(uname)" = "Darwin" ] && command -v caffeinate >/dev/null 2>&1; then
    INHIBIT="caffeinate -i"
elif command -v systemd-inhibit >/dev/null 2>&1; then
    INHIBIT="systemd-inhibit --what=sleep:idle --who=TBHM --why=security-scan --mode=block"
fi

# Spawn detached
exec $INHIBIT "$SCRIPT_DIR/tbhm" --background "$@"
