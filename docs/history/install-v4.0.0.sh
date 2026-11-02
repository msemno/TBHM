#!/usr/bin/env bash
# TBHM v4.0.0-unified-safe installer
# Installs TBHM dependencies while isolating optional Python/Node toolchains.

set -Eeuo pipefail

GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
RESET='\033[0m'
info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[x]${RESET} $*"; }

ROOT="$(cd "$(dirname "$0")" && pwd)"
TOOL_HOME="${TBHM_TOOL_HOME:-$HOME/.local/share/tbhm-tools}"
LOCAL_BIN="$HOME/.local/bin"
INSTALL_STATE_DIR="${TBHM_INSTALL_STATE_DIR:-$HOME/.local/state/tbhm/install}"
mkdir -p "$TOOL_HOME/venvs" "$LOCAL_BIN" "$INSTALL_STATE_DIR"
export PATH="$LOCAL_BIN:$HOME/go/bin:$HOME/.cargo/bin:$PATH"

# Install one Python CLI/library in its own environment. This deliberately does
# not touch Kali's distro site-packages or the shared user site-packages.
install_isolated_python_tool() {
    local tool_id="$1" package="$2" executable="${3:-}" python_bin="${4:-python3}"
    local venv="$TOOL_HOME/venvs/$tool_id"
    local vpy="$venv/bin/python"
    if [ -n "$executable" ] && command -v "$executable" >/dev/null 2>&1; then
        local existing resolved
        existing="$(command -v "$executable")"
        resolved="$(readlink -f "$existing" 2>/dev/null || printf '%s' "$existing")"
        if [[ "$resolved" == "$TOOL_HOME/venvs/"* ]] || [[ "$resolved" == *"/pipx/venvs/"* ]] || [[ "$existing" == /usr/bin/* ]]; then
            info "  $tool_id: already present in an isolated/distro environment ($existing)"
            return 0
        fi
        if [[ "$existing" == "$LOCAL_BIN/"* ]]; then
            warn "  $tool_id: legacy shared-user installation detected at $existing; replacing its launcher with an isolated environment"
        else
            info "  $tool_id: already present ($existing)"
            return 0
        fi
    fi
    if ! command -v "$python_bin" >/dev/null 2>&1; then
        warn "  $tool_id skipped: compatible interpreter '$python_bin' is unavailable"
        return 2
    fi
    info "  installing $tool_id in isolated environment: $venv"
    "$python_bin" -m venv "$venv" || { warn "  $tool_id: unable to create virtual environment"; return 1; }
    "$vpy" -m pip install --disable-pip-version-check --upgrade pip setuptools wheel \
        || { warn "  $tool_id: bootstrap failed"; return 1; }
    "$vpy" -m pip install --disable-pip-version-check "$package" \
        || { warn "  $tool_id: package installation failed"; return 1; }
    if [ -n "$executable" ] && [ -x "$venv/bin/$executable" ]; then
        ln -sfn "$venv/bin/$executable" "$LOCAL_BIN/$executable"
    fi
    printf '{"tool":"%s","package":"%s","python":"%s","venv":"%s"}\n' \
        "$tool_id" "$package" "$python_bin" "$venv" > "$venv/.tbhm-install.json"
}

npm_user_install() {
    if ! command -v npm >/dev/null 2>&1; then
        warn "  npm is unavailable; skipped: $*"
        return 2
    fi
    npm install --global --prefix "$HOME/.local" "$@"
}

apt_package_installed() {
    command -v dpkg-query >/dev/null 2>&1 || return 1
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'
}

info "TBHM v4.0.0-unified-safe installer starting"
info "Working directory: $ROOT"

# ──────────────────────────────────────────────────────────────────────────────
# OS detection
# ──────────────────────────────────────────────────────────────────────────────
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    PKG_INSTALL="sudo apt-get -o Acquire::ForceIPv4=true install -y --fix-missing"
    PKG_UPDATE="sudo apt-get -o Acquire::ForceIPv4=true update"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PKG_INSTALL="brew install"
    PKG_UPDATE="brew update"
else
    warn "Unsupported OS: $OSTYPE -- attempting Linux defaults"
    OS="linux"
    PKG_INSTALL="sudo apt-get -o Acquire::ForceIPv4=true install -y --fix-missing"
    PKG_UPDATE="sudo apt-get -o Acquire::ForceIPv4=true update"
fi
info "OS detected: $OS"

# ──────────────────────────────────────────────────────────────────────────────
# Python 3 + pip + venv
# ──────────────────────────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not installed -- install it first"
    exit 1
fi
PY_VER=$(python3 -c 'import sys; print("%d.%d"%sys.version_info[:2])')
info "Python: $PY_VER"

# Install Python deps
info "Installing TBHM core Python dependencies..."
python3 -m pip install --user --break-system-packages -r "$ROOT/requirements.txt" \
  || python3 -m pip install --user -r "$ROOT/requirements.txt" \
  || warn "TBHM core dependency installation reported an issue"
# Report pre-existing environment conflicts truthfully. Optional tool installs
# below are isolated and therefore cannot add new conflicts to this environment.
python3 -m pip check || warn "The current user/system Python already contains dependency conflicts; optional TBHM tools will remain isolated."

# ──────────────────────────────────────────────────────────────────────────────
# Go install (needed for ProjectDiscovery + others)
# ──────────────────────────────────────────────────────────────────────────────
if ! command -v go >/dev/null 2>&1; then
    info "Installing Go..."
    if [ "$OS" = "linux" ]; then
        GO_VER=1.22.5
        wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
        echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> ~/.bashrc
        rm /tmp/go.tar.gz
    else
        $PKG_INSTALL go
    fi
else
    info "Go already installed: $(go version)"
fi
export PATH="$HOME/go/bin:$PATH"

# ──────────────────────────────────────────────────────────────────────────────
# Go tools
# ──────────────────────────────────────────────────────────────────────────────
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/PentestPad/subzy@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/Josue87/gotator@latest"
    "github.com/gwen001/github-subdomains@latest"
    "github.com/jaeles-project/jaeles@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/lc/subjs@latest"
)

go_tool_name() {
    local mod="${1%@*}"
    local base
    base="$(basename "$mod")"
    # Some Go modules use semantic-import suffixes like /v2 or /v3. The actual
    # binary is the parent directory name, not "v2". Without this, installer
    # falsely checks/prints a command named v2 and skips dalfox/ffuf installs.
    if [[ "$base" =~ ^v[0-9]+$ ]]; then
        base="$(basename "$(dirname "$mod")")"
    fi
    # Module name differs from binary name.
    if [ "$base" = "chaos-client" ]; then base="chaos"; fi
    echo "$base"
}

tool_is_usable() {
    local name="$1"
    command -v "$name" >/dev/null 2>&1 || return 1
    # httpx is commonly confused with the Python package/CLI. For TBHM we need
    # ProjectDiscovery httpx. If the existing binary does not answer like PD
    # httpx, force go install into $HOME/go/bin.
    if [ "$name" = "httpx" ]; then
        httpx -version 2>&1 | grep -Eiq 'projectdiscovery|httpx' || return 1
    fi
    return 0
}

info "Installing Go-based security tools (this can take a while)..."
for tool in "${GO_TOOLS[@]}"; do
    name="$(go_tool_name "$tool")"
    if tool_is_usable "$name"; then
        info "  $name: already installed"
    else
        info "  installing $name..."
        go install "$tool" 2>&1 | tail -2 || warn "  $name failed -- you can retry later"
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
# Python-based tools (sqlmap, arjun, trufflehog)
# ──────────────────────────────────────────────────────────────────────────────
info "Installing Python-based tools in isolated environments..."
install_isolated_python_tool "arjun" "arjun" "arjun" || warn "arjun install failed or was skipped"

if [ "$OS" = "linux" ]; then
    if ! command -v sqlmap >/dev/null 2>&1; then
        $PKG_INSTALL sqlmap || warn "sqlmap install via apt failed"
    fi
    if ! command -v whois >/dev/null 2>&1; then
        $PKG_INSTALL whois || true
    fi
    if ! command -v dig >/dev/null 2>&1; then
        $PKG_INSTALL dnsutils || true
    fi
    # New tools for v2.1+: ports + deep_scan + screenshots
    info "Installing v2.1+ additional scanners (apt)..."
    for pkg in nmap masscan nikto amass chromium wapiti python3-paramspider; do
        if ! command -v "${pkg/python3-/}" >/dev/null 2>&1 && ! apt_package_installed "$pkg"; then
            $PKG_INSTALL "$pkg" 2>/dev/null || warn "  $pkg not available via apt"
        else
            info "  $pkg: already present"
        fi
    done
    # v2.22-redteam optional enterprise tools (safe inventory/static review)
    info "Installing v2.22-redteam optional enterprise tools (apt)..."
    for pkg in ldap-utils file binutils binwalk iw network-manager tshark snmp; do
        if ! apt_package_installed "$pkg"; then
            $PKG_INSTALL "$pkg" 2>/dev/null || warn "  $pkg not available via apt"
        else
            info "  $pkg: already present"
        fi
    done

    # findomain (binary not in apt; download release)
    if ! command -v findomain >/dev/null 2>&1; then
        info "Installing findomain..."
        wget -qO /tmp/findomain.zip https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip \
          && unzip -q -o /tmp/findomain.zip -d /tmp/ \
          && sudo install /tmp/findomain /usr/local/bin/ \
          && info "  findomain installed" \
          || warn "  findomain install failed"
    fi
fi

# v3.9: Optional source-security adapter bundle. Kept opt-in because Semgrep,
# Checkov and dependency tooling can consume significant disk/RAM and may clash
# with distro-managed Python environments.
if [ "${INSTALL_CODE_SECURITY:-0}" = "1" ]; then
    info "Installing optional v3.9 source-security adapters in isolated environments..."
    install_isolated_python_tool "semgrep" "semgrep" "semgrep" || warn "semgrep install failed or was skipped"
    install_isolated_python_tool "bandit" "bandit" "bandit" || warn "bandit install failed or was skipped"
    install_isolated_python_tool "ruff" "ruff" "ruff" || warn "ruff install failed or was skipped"
    install_isolated_python_tool "njsscan" "njsscan" "njsscan" || warn "njsscan install failed or was skipped"
    install_isolated_python_tool "checkov" "checkov" "checkov" || warn "checkov install failed or was skipped"
    install_isolated_python_tool "detect-secrets" "detect-secrets" "detect-secrets" || warn "detect-secrets install failed or was skipped"
    install_isolated_python_tool "safety" "safety" "safety" || warn "safety install failed or was skipped"

    if command -v go >/dev/null 2>&1 && ! command -v gosec >/dev/null 2>&1; then
        go install github.com/securego/gosec/v2/cmd/gosec@latest \
          || warn "gosec install failed"
    fi
    if ! command -v eslint >/dev/null 2>&1; then
        npm_user_install eslint eslint-plugin-security \
          || warn "eslint/security plugin install failed or npm is unavailable"
    fi
    if [ "$OS" = "linux" ] && ! command -v hadolint >/dev/null 2>&1; then
        if apt-cache show hadolint >/dev/null 2>&1; then
            $PKG_INSTALL hadolint || warn "hadolint apt installation failed"
        else
            warn "hadolint is unavailable in the configured apt repositories; it remains an optional adapter"
        fi
    fi
    if ! command -v syft >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
        info "  installing syft with the upstream installer into $LOCAL_BIN..."
        SYFT_INSTALLER="$(mktemp)"
        if curl -fsSL https://get.anchore.io/syft -o "$SYFT_INSTALLER"; then
            sh "$SYFT_INSTALLER" -b "$LOCAL_BIN" || warn "syft installer failed"
        else
            warn "syft installer download failed"
        fi
        rm -f "$SYFT_INSTALLER"
    fi
    info "Heavy/platform tools (CodeQL, SonarQube, DefectDojo, Mega-Linter, Snyk) remain external/import-only."
else
    info "Skipping optional source-security bundle. Enable with: INSTALL_CODE_SECURITY=1 ./install.sh"
fi

# v3.9.2: Optional reverse-engineering bundle. Native TBHM analysis remains
# static. Debugger/instrumentation/sandbox outputs are imported as evidence;
# untrusted binaries are not launched directly by the orchestrator.
if [ "${INSTALL_REVERSE_TOOLING:-0}" = "1" ]; then
    info "Installing optional v3.9.2 reverse-engineering tooling..."
    if [ "$OS" = "linux" ]; then
        for pkg in file binutils gdb qemu-user qemu-user-static qemu-system qemu-utils podman tshark radare2 binwalk squashfs-tools p7zip-full unar zstd lz4; do
            if ! apt_package_installed "$pkg"; then
                $PKG_INSTALL "$pkg" 2>/dev/null || warn "  $pkg not available via this apt repository"
            else
                info "  $pkg: already present"
            fi
        done
    fi
    if ! command -v unblob >/dev/null 2>&1; then
        if [ "$OS" = "linux" ] && apt-cache show unblob >/dev/null 2>&1; then
            $PKG_INSTALL unblob || warn "unblob apt installation failed"
        else
            install_isolated_python_tool "unblob" "unblob" "unblob" || warn "unblob install failed or was skipped"
        fi
    fi
    install_isolated_python_tool "flare-capa" "flare-capa" "capa" || warn "capa install failed or was skipped"
    install_isolated_python_tool "flare-floss" "flare-floss" "floss" || warn "floss install failed or was skipped"
    install_isolated_python_tool "frida-tools" "frida-tools" "frida" || warn "frida-tools install failed or was skipped"
    if [ "${INSTALL_ANGR:-0}" = "1" ]; then
        install_isolated_python_tool "angr" "angr" "" || warn "angr installation failed or was skipped"
    else
        info "Skipping heavy angr dependency. Enable with: INSTALL_REVERSE_TOOLING=1 INSTALL_ANGR=1 ./install.sh"
    fi
    info "Ghidra, UEFITool/UEFIExtract, JADX/Android SDK, IDA Pro, Binary Ninja, WinDbg/x64dbg, CAPE/Cuckoo and commercial sandboxes remain operator-managed integrations."
    info "EMBA remains operator-managed because it has its own VM/Docker installer. Set EMBA_HOME or use --emba-path after installation."
    info "RouterSploit remains operator-managed. TBHM catalogs modules and imports results but never launches exploit/credential/payload modules."
else
    info "Skipping optional reverse-engineering bundle. Enable with: INSTALL_REVERSE_TOOLING=1 ./install.sh"
fi

# v3.9: Optional local Ollama runtime. Model files are never downloaded
# automatically; the operator must review/import an approved GGUF or pull an
# approved model explicitly. This prevents surprise multi-GB downloads.
if [ "${INSTALL_OLLAMA:-0}" = "1" ]; then
    if command -v ollama >/dev/null 2>&1; then
        info "Ollama already installed: $(ollama --version 2>/dev/null | head -1)"
    elif [ "$OS" = "linux" ]; then
        info "Installing Ollama runtime (no model download)..."
        TMP_OLLAMA_INSTALL="$(mktemp)"
        if curl -fsSL https://ollama.com/install.sh -o "$TMP_OLLAMA_INSTALL"; then
            sh "$TMP_OLLAMA_INSTALL" || warn "Ollama installer failed"
        else
            warn "Unable to download Ollama installer"
        fi
        rm -f "$TMP_OLLAMA_INSTALL"
    else
        warn "Install Ollama manually on macOS, then import the approved model."
    fi
else
    info "Skipping Ollama runtime. Enable with: INSTALL_OLLAMA=1 ./install.sh"
fi

# v3.9.4: Optional first-time AI Control Plane bootstrap. Creates the portable
# $TBHM_AI_HOME (default ~/.local/share/tbhm-ai), initializes the SQLite store,
# indexes the tool source, and (unless AI_NO_PULL=1) pulls the advisor +
# embedding models via the vetted Ollama path. State lives OUTSIDE this tree so
# it survives ZIP replacement / laptop moves.
if [ "${INSTALL_AI:-0}" = "1" ]; then
    info "Bootstrapping AI Control Plane (portable co-pilot)..."
    AI_HOME_DIR="${TBHM_AI_HOME:-$HOME/.local/share/tbhm-ai}"
    info "  AI home: $AI_HOME_DIR"
    if [ "${AI_NO_PULL:-0}" = "1" ] || ! command -v ollama >/dev/null 2>&1; then
        python3 ./tbhm.py --ai-init --ai-no-pull || warn "AI init (no-pull) reported an issue"
        info "  Models not pulled. Later: ollama pull nomic-embed-text && ./tbhm.py --ai-init"
    else
        python3 ./tbhm.py --ai-init \
            --ai-advisor-model "${TBHM_LOCAL_LLM_MODEL:-qwen3-cybersec:4b}" \
            --ai-embedding-model "${TBHM_AI_EMBED_MODEL:-nomic-embed-text}" \
            || warn "AI init reported an issue (check Ollama and models)"
    fi
    info "  AI health check: ./tbhm.py --ai-doctor"
else
    info "Skipping AI Control Plane. Enable with: INSTALL_AI=1 ./install.sh"
fi

# v2.3: Optional Playwright for headless crawl (heavy, opt-in)
# ──────────────────────────────────────────────────────────────────────────────
# v3.9.6 optional extended SAFE integrations.
# The helper reads the catalog but executes only vetted safe_cli/library/feed
# recipes. Approval-only, C2, phishing, credential/coercion, disruptive
# wireless/OT, commercial and import-only tools are never auto-installed.
# ──────────────────────────────────────────────────────────────────────────────
EXTENDED_BUNDLES=()
[ "${INSTALL_CORPORATE_OSINT:-0}" = "1" ] && EXTENDED_BUNDLES+=("corporate-osint,network-domain-intelligence,image-video-analysis")
[ "${INSTALL_STANDARDS_INTEL:-0}" = "1" ] && EXTENDED_BUNDLES+=("standards,vulnerability-intelligence")
[ "${INSTALL_CLOUD_SECURITY:-0}" = "1" ] && EXTENDED_BUNDLES+=("cloud-posture,kubernetes,policy")
[ "${INSTALL_IDENTITY_SECURITY:-0}" = "1" ] && EXTENDED_BUNDLES+=("identity-security")
[ "${INSTALL_MOBILE_RE:-0}" = "1" ] && EXTENDED_BUNDLES+=("mobile-reverse,reverse-malware")
[ "${INSTALL_DATA_ANALYSIS:-0}" = "1" ] && EXTENDED_BUNDLES+=("data-analysis")
[ "${INSTALL_PURPLE_TEAM:-0}" = "1" ] && EXTENDED_BUNDLES+=("purple-team,network-monitoring,forensics")
[ "${INSTALL_API_EXTENDED:-0}" = "1" ] && EXTENDED_BUNDLES+=("api-testing,web-testing,tls-pki")
[ "${INSTALL_CODE_EXTENDED:-0}" = "1" ] && EXTENDED_BUNDLES+=("code-analysis,fuzzing")
[ "${INSTALL_CICD_SECURITY:-0}" = "1" ] && EXTENDED_BUNDLES+=("ci-cd-security")
if [ "${INSTALL_ALL_SAFE_EXTENDED:-0}" = "1" ]; then
    EXTENDED_BUNDLES=("all-safe")
fi
if [ ${#EXTENDED_BUNDLES[@]} -gt 0 ]; then
    info "Installing selected v3.9.7.5 safe extended bundles..."
    for bundle in "${EXTENDED_BUNDLES[@]}"; do
        SAFE_BUNDLE_NAME="${bundle//,/__}"
        python3 "$ROOT/scripts/install_extended_tools.py" --bundle "$bundle" --apply \
          --state-file "$INSTALL_STATE_DIR/extended-${SAFE_BUNDLE_NAME}.json" \
          || warn "Some optional tools in bundle '$bundle' genuinely failed; expected incompatibilities are recorded as skips"
    done
else
    info "Skipping v3.9.7.5 extended safe bundles. Examples:"
    info "  INSTALL_CORPORATE_OSINT=1 INSTALL_DATA_ANALYSIS=1 ./install.sh"
    info "  INSTALL_CLOUD_SECURITY=1 INSTALL_IDENTITY_SECURITY=1 ./install.sh"
    info "  INSTALL_CICD_SECURITY=1 ./install.sh"
    info "  INSTALL_ALL_SAFE_EXTENDED=1 ./install.sh"
fi
warn "High-risk/operator tooling is catalogued for approval/import only and is never installed or executed automatically."

if [ "${INSTALL_PLAYWRIGHT:-0}" = "1" ]; then
    info "Installing Playwright in an isolated environment (headless crawler)..."
    install_isolated_python_tool "playwright" "playwright" "playwright" || warn "Playwright Python package install failed"
    PLAYWRIGHT_PY="$TOOL_HOME/venvs/playwright/bin/python"
    if [ -x "$PLAYWRIGHT_PY" ]; then
        if ! "$PLAYWRIGHT_PY" -m playwright install chromium; then
            if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1; then
                warn "Playwright-managed Chromium failed to install; TBHM will try the existing system Chromium as a compatibility fallback"
            else
                warn "Playwright browser installation failed and no system Chromium fallback was found"
            fi
        fi
    fi
else
    info "Skipping Playwright (headless crawl). To enable: INSTALL_PLAYWRIGHT=1 ./install.sh"
fi

# trufflehog
if ! command -v trufflehog >/dev/null 2>&1; then
    info "installing trufflehog..."
    if [ "$OS" = "linux" ]; then
        TRUFFLE_INSTALLER="$(mktemp)"
        if curl --fail --silent --show-error --location --retry 2 --retry-delay 2 \
          --connect-timeout 15 --max-time 120 \
          https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
          --output "$TRUFFLE_INSTALLER"; then
            if sh "$TRUFFLE_INSTALLER" -b "$LOCAL_BIN"; then
                info "  trufflehog installed in $LOCAL_BIN"
            else
                warn "trufflehog installer returned a non-zero status"
            fi
        else
            warn "trufflehog installer download failed"
        fi
        rm -f "$TRUFFLE_INSTALLER"
    else
        brew install trufflehog || warn "trufflehog brew install failed"
    fi
fi

# v2.8: retire.js — JS library CVE scanner (used by vuln_scan_extended)
if ! command -v retire >/dev/null 2>&1; then
    info "installing retire.js (Node — JS library vulnerability scanner)..."
    if command -v npm >/dev/null 2>&1; then
        npm_user_install retire || \
            warn "  retire.js install failed or npm is unavailable — vuln_scan_extended will skip it"
    else
        warn "  npm not found — install Node.js first, then re-run INSTALL_CODE_SECURITY=1 ./install.sh"
    fi
fi

# v2.8: wpscan — WordPress security scanner (auto-runs if WP detected)
if ! command -v wpscan >/dev/null 2>&1; then
    info "installing wpscan (Ruby gem — WordPress vulnerability scanner)..."
    if command -v gem >/dev/null 2>&1; then
        if gem install --user-install --no-document wpscan; then
            GEM_USER_DIR="$(ruby -e 'print Gem.user_dir' 2>/dev/null || true)"
            if [ -n "$GEM_USER_DIR" ] && [ -x "$GEM_USER_DIR/bin/wpscan" ]; then
                ln -sf "$GEM_USER_DIR/bin/wpscan" "$LOCAL_BIN/wpscan"
                info "  wpscan exposed at $LOCAL_BIN/wpscan"
            else
                warn "  wpscan installed but its user executable was not found"
            fi
        else
            warn "  wpscan gem install failed — vuln_scan_extended will skip WP checks"
        fi
    else
        warn "  Ruby gem not found — install ruby+rubygems, then re-run the installer"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# SecLists check / install
# ──────────────────────────────────────────────────────────────────────────────
SECLISTS_FOUND=""
for path in /usr/share/seclists /usr/share/SecLists /opt/SecLists "$HOME/SecLists"; do
    if [ -d "$path/Discovery" ]; then
        SECLISTS_FOUND="$path"
        break
    fi
done

if [ -n "$SECLISTS_FOUND" ]; then
    info "SecLists found at: $SECLISTS_FOUND"
else
    warn "SecLists not found in standard locations"
    if [ "$OS" = "linux" ] && command -v apt >/dev/null 2>&1; then
        info "Trying: apt install seclists..."
        $PKG_INSTALL seclists 2>/dev/null && SECLISTS_FOUND="/usr/share/seclists"
    fi
    if [ -z "$SECLISTS_FOUND" ]; then
        info "Cloning SecLists to /opt/SecLists..."
        if [ -w /opt ]; then
            git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists \
              && SECLISTS_FOUND="/opt/SecLists"
        else
            sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists \
              && SECLISTS_FOUND="/opt/SecLists"
        fi
    fi
fi
if [ -n "$SECLISTS_FOUND" ]; then
    info "✓ SecLists ready at: $SECLISTS_FOUND"
    info "  (you can override via SECLISTS env var)"
else
    warn "SecLists not installed -- TBHM will fall back to bundled wordlists (smaller coverage)"
    warn "Install manually: git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Permissions
# ──────────────────────────────────────────────────────────────────────────────
chmod +x "$ROOT/tbhm.py" 2>/dev/null || true
chmod +x "$ROOT/install.sh" 2>/dev/null || true
chmod +x "$ROOT/scripts/install_extended_tools.py" "$ROOT/scripts/installer_doctor.py"   "$ROOT/scripts/repair_legacy_python_environment.py" "$ROOT/scripts/update_intel_feeds.py" 2>/dev/null || true
chmod +x "$ROOT/integration_test_v395.py" 2>/dev/null || true

# ──────────────────────────────────────────────────────────────────────────────
# Final summary
# ──────────────────────────────────────────────────────────────────────────────
show_required_tool() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        echo "    [✓] $name"
    else
        echo "    [✗] $name (required for this coverage group)"
    fi
}
show_optional_tool() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        echo "    [✓] $name"
    else
        echo "    [–] $name (optional/unavailable)"
    fi
}

python3 "$ROOT/scripts/installer_doctor.py" --json > "$INSTALL_STATE_DIR/installer-doctor.json"   || warn "Installer doctor could not write its state record"
python3 "$ROOT/scripts/repair_legacy_python_environment.py" --json   > "$INSTALL_STATE_DIR/legacy-python-cleanup-plan.json"   || warn "Legacy Python cleanup planner could not write its state record"

echo
echo "─── Install summary ───"
echo "  CORE recon:"
for t in subfinder assetfinder amass httpx dnsx; do show_required_tool "$t"; done
echo "  Discovery:"
for t in waybackurls gau katana gospider hakrawler subjs gotator; do show_required_tool "$t"; done
echo "  Content discovery:"
for t in ffuf nikto; do show_required_tool "$t"; done
echo "  Port scanning:"
for t in naabu nmap masscan; do show_required_tool "$t"; done
echo "  Vuln scanning:"
for t in nuclei dalfox subzy jaeles wapiti sqlmap; do show_required_tool "$t"; done

# v2.11: THE critical step that was missing — nuclei is useless without templates.
if command -v nuclei >/dev/null 2>&1; then
    info "Updating nuclei templates (this is what fixes 'nuclei finds nothing')..."
    nuclei -update-templates -silent 2>/dev/null || warn "template update failed — re-run: nuclei -update-templates"
    TPL_COUNT=$(find "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" "$HOME/.config/nuclei/templates" -name '*.yaml' 2>/dev/null | wc -l | tr -d ' ')
    info "nuclei templates installed: ${TPL_COUNT:-0}"
    CUSTOM_BUILD="$(cd "$(dirname "$0")" && pwd)/nuclei-templates/_build_templates.py"
    CUSTOM_DIR="$(cd "$(dirname "$0")" && pwd)/nuclei-templates/tbhm"
    if [ ! -d "$CUSTOM_DIR" ] || [ -z "$(find "$CUSTOM_DIR" -name '*.yaml' 2>/dev/null | head -1)" ]; then
        if [ -f "$CUSTOM_BUILD" ]; then python3 "$CUSTOM_BUILD" >/dev/null 2>&1 || true; fi
    fi
    if [ -d "$CUSTOM_DIR" ]; then
        CUSTOM_COUNT=$(find "$CUSTOM_DIR" -name '*.yaml' 2>/dev/null | wc -l | tr -d ' ')
        info "TBHM custom templates bundled: ${CUSTOM_COUNT:-0} (low/info coverage)"
    fi
fi
echo "  Visual / params / secrets:"
for t in gowitness arjun trufflehog chaos github-subdomains findomain; do show_required_tool "$t"; done
echo "  Source security / local AI (optional):"
for t in semgrep bandit ruff njsscan gitleaks trivy grype checkov terrascan tfsec gosec eslint detect-secrets syft safety hadolint s0 ollama nvidia-smi; do show_optional_tool "$t"; done
echo "  Reverse engineering (optional):"
for t in file readelf objdump nm r2 rizin analyzeHeadless capa floss gdb frida qemu-x86_64; do show_optional_tool "$t"; done
echo "  Firmware analysis (optional):"
for t in unblob binwalk unsquashfs sasquatch checksec emba qemu-mipsel-static qemu-mips-static qemu-arm-static qemu-aarch64-static; do show_optional_tool "$t"; done
echo "  Misc:"
for t in whois dig python3 anew qsreplace gf unfurl; do show_required_tool "$t"; done
echo
echo "─── API keys (improve recon coverage dramatically) ───"
for key in CHAOS_KEY GITHUB_TOKEN SHODAN_API_KEY CENSYS_API_ID CENSYS_API_SECRET VIRUSTOTAL_API_KEY; do
    if [ -n "${!key:-}" ]; then echo "  [✓] $key set"; else echo "  [–] $key not set (optional coverage reduction)"; fi
done
echo
info "Done. Quick test:"
info "  ./tbhm.py -d testphp.vulnweb.com -y --quick"
info "Optional source bundle: INSTALL_CODE_SECURITY=1 ./install.sh"
info "Optional local runtime: INSTALL_OLLAMA=1 ./install.sh (model import remains manual)"
info "Optional reverse tooling: INSTALL_REVERSE_TOOLING=1 ./install.sh"
info "Optional AI co-pilot:   INSTALL_OLLAMA=1 INSTALL_AI=1 ./install.sh   (portable, non-authoritative)"
info "Optional corporate OSINT/data: INSTALL_CORPORATE_OSINT=1 INSTALL_DATA_ANALYSIS=1 ./install.sh"
info "Optional cloud/identity: INSTALL_CLOUD_SECURITY=1 INSTALL_IDENTITY_SECURITY=1 ./install.sh"
info "Optional CI/CD integrity: INSTALL_CICD_SECURITY=1 ./install.sh"
info "All vetted safe extended tools: INSTALL_ALL_SAFE_EXTENDED=1 ./install.sh"
info "Installer diagnostics: python3 scripts/installer_doctor.py"
info "Legacy v3.9.7.2 cleanup plan: python3 scripts/repair_legacy_python_environment.py"
info "Apply conservative top-level cleanup only after review: python3 scripts/repair_legacy_python_environment.py --apply"
info "Install state: $INSTALL_STATE_DIR"
info "  After any code change: ./tbhm.py --ai-sync-tool   | Health: ./tbhm.py --ai-doctor"
info "  New laptop / new ZIP:  copy \$TBHM_AI_HOME across, then ./tbhm.py --ai-migrate"
echo
warn "Reminder: TBHM aggregates many tools but is NOT a replacement for"
warn "Burp Suite Pro or ZAP. Every finding must be manually verified."
