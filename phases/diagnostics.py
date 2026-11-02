"""
Phase: diagnostics

The user reported: "the tools don't find anything — impossible".
Most often, this is because:
  - nuclei is installed but templates were never downloaded
  - subfinder has no provider API keys → only finds passive crt.sh data
  - amass times out without config
  - retire / wpscan / dalfox not installed at all
  - chromium / Playwright not installed → smart_crawl falls back to static
  - networking issues block specific sources

This phase runs FIRST (right after preflight) and prints a clear status
table so the user knows what's actually going to fire.

Writes: <output>/diagnostics.txt + a summary finding (INFO severity).
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path

from core import bootstrap
from core.hardware_profile import detect as detect_hardware


# (tool_name, what_it_does, where_used, install_hint)
TOOL_CHECKS = [
    # core recon
    ("subfinder",   "subdomain discovery (passive)",   "recon",
     "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("amass",       "subdomain discovery (active)",    "recon",
     "snap install amass / apt install amass"),
    ("httpx",       "alive host probing",              "recon",
     "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("dnsx",        "DNS resolution / takeover hints", "recon",
     "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    # port scanning
    ("naabu",       "fast port scanner",               "ports",
     "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ("nmap",        "service-version port scanner",    "ports",
     "apt install nmap / brew install nmap"),
    ("masscan",     "ultra-fast port scanner",         "ports",
     "apt install masscan"),
    # discovery / crawl
    ("katana",      "JS-aware crawler",                "smart_crawl, discovery",
     "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("gau",         "wayback URL collector",           "discovery",
     "go install -v github.com/lc/gau/v2/cmd/gau@latest"),
    ("waybackurls", "wayback URLs (legacy)",           "discovery",
     "go install github.com/tomnomnom/waybackurls@latest"),
    ("paramspider", "URL parameter mining",            "discovery",
     "git clone https://github.com/devanshbatham/ParamSpider"),
    ("ffuf",        "content discovery fuzzer",        "content_discovery",
     "go install -v github.com/ffuf/ffuf/v2@latest"),
    ("feroxbuster", "alt content discovery",           "content_discovery",
     "apt install feroxbuster"),
    # vuln scanners
    ("nuclei",      "template-based vuln scanner",     "vuln_scan, nuclei_extended",
     "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("dalfox",      "context-aware XSS scanner",       "vuln_scan_extended",
     "go install -v github.com/hahwul/dalfox/v2@latest"),
    ("retire",      "JS library CVE scanner",          "vuln_scan_extended",
     "npm install -g retire"),
    ("wpscan",      "WordPress scanner",               "vuln_scan_extended",
     "gem install wpscan"),
    ("nikto",       "old-school web scanner",          "deep_scan",
     "apt install nikto"),
    ("wapiti",      "web app auditor",                 "deep_scan",
     "apt install wapiti / pip install wapiti3"),
    # secrets
    ("trufflehog",  "verified secret scanner",         "secrets_misc",
     "curl -sSfL trufflesecurity.com/install.sh | sh"),
    ("gitleaks",    "git secret scanner",              "secrets_misc",
     "go install github.com/zricethezav/gitleaks/v8@latest"),
    # special
    ("sqlmap",      "deep SQLi exploitation",          "audit (optional)",
     "apt install sqlmap / pip install sqlmap"),
    ("gowitness",   "screenshot tool",                 "visual",
     "go install -v github.com/sensepost/gowitness@latest"),
    ("curl",        "HTTP request tool",               "curl_verify, curl_probes",
     "(built-in on most systems)"),
    # enterprise red-team safe expansion
    ("ldapsearch",  "read-only LDAP/AD inventory",       "ad_identity_safe",
     "apt install ldap-utils"),
    ("iw",          "passive wireless interface scan",   "wireless_physical_soc",
     "apt install iw"),
    ("nmcli",       "Wi-Fi inventory fallback",          "wireless_physical_soc",
     "apt install network-manager"),
    ("binwalk",     "firmware signature/static review",  "firmware_reverse_safe",
     "apt install binwalk"),
    ("strings",     "firmware/binary strings review",    "firmware_reverse_safe",
     "binutils (usually installed)"),
    ("git",         "VCS",                             "discovery, secrets",
     "apt install git"),
    ("chromium",    "browser for headless crawl",      "smart_crawl",
     "apt install chromium"),
    # v3.9 local source-security and local-model adapters (all optional)
    ("semgrep",     "multi-language SAST",              "sast_tooling, code_security_tooling",
     "python3 -m pip install semgrep"),
    ("bandit",      "Python security SAST",             "code_security_tooling",
     "python3 -m pip install bandit"),
    ("ruff",        "fast Python lint/security rules",   "code_security_tooling",
     "python3 -m pip install ruff"),
    ("njsscan",     "JavaScript/Node SAST",             "code_security_tooling",
     "python3 -m pip install njsscan"),
    ("trivy",       "SCA/container/IaC scanner",        "code_security_tooling",
     "install Trivy from the official package/release"),
    ("grype",       "filesystem/container SCA",         "code_security_tooling",
     "install Grype from the official release"),
    ("checkov",     "IaC misconfiguration scanner",     "code_security_tooling",
     "python3 -m pip install checkov"),
    ("terrascan",   "Terraform/Kubernetes IaC scanner", "code_security_tooling",
     "install Terrascan from the official release"),
    ("tfsec",       "Terraform security scanner",       "code_security_tooling",
     "install tfsec from the official release"),
    ("gosec",       "Go source SAST",                   "code_security_tooling",
     "go install github.com/securego/gosec/v2/cmd/gosec@latest"),
    ("eslint",      "JavaScript/TypeScript lint adapter", "code_security_tooling",
     "npm install -g eslint eslint-plugin-security"),
    ("detect-secrets", "local secret detection",         "code_security_tooling",
     "python3 -m pip install detect-secrets"),
    ("syft",        "SBOM generation",                  "code_security_tooling",
     "install Syft from the official release"),
    ("safety",      "Python dependency advisory scan",  "code_security_tooling",
     "python3 -m pip install safety"),
    ("hadolint",    "Dockerfile lint/security review",  "code_security_tooling",
     "apt install hadolint or use the official binary"),
    ("s0",          "deterministic source orchestrator", "source_orchestration_tooling",
     "install s0-cli or provide --s0-dir"),
    ("ollama",      "local LLM runtime",                "local_llm_triage, report",
     "install Ollama, then import/create the approved local model"),
    ("nvidia-smi",  "NVIDIA GPU/VRAM detection",        "local LLM hardware sizing",
     "install the matching NVIDIA driver for Kali"),
    ("ldapdomaindump", "AD inventory export (import supported)", "ad_access_assessment import",
     "python3 -m pip install ldapdomaindump"),
    ("bloodhound-python", "BloodHound collection (external/import workflow)", "ad_access_assessment import",
     "apt install bloodhound.py or python3 -m pip install bloodhound"),
    # v3.9.2 reverse-engineering workflow (static by default; dynamic evidence import)
    ("file",        "binary type/architecture fingerprinting", "reverse_triage",
     "apt install file"),
    ("readelf",     "ELF headers/sections/dynamic metadata",   "reverse_triage",
     "apt install binutils"),
    ("objdump",     "binary headers/imports/disassembly",      "reverse_triage",
     "apt install binutils"),
    ("nm",          "binary symbol extraction",                "reverse_triage",
     "apt install binutils"),
    ("r2",          "scriptable Radare2 static analysis",      "reverse_static_analysis",
     "apt install radare2 or install from the official release"),
    ("rizin",       "scriptable Rizin static analysis",        "reverse_static_analysis",
     "install Rizin from the official release"),
    ("analyzeHeadless", "Ghidra headless decompilation/export", "reverse_static_analysis",
     "install Ghidra and add support/analyzeHeadless to PATH or set --reverse-ghidra-home"),
    ("capa",        "binary capability identification",        "reverse_triage",
     "python3 -m pip install flare-capa"),
    ("floss",       "decoded/stack string extraction",         "reverse_triage",
     "python3 -m pip install flare-floss"),
    ("gdb",         "controlled Linux debugger evidence",      "reverse_dynamic_evidence import",
     "apt install gdb"),
    ("frida",       "dynamic instrumentation evidence",        "reverse_dynamic_evidence import",
     "python3 -m pip install frida-tools"),
    ("qemu-x86_64", "isolated/cross-architecture emulation",   "external sandbox workflow",
     "apt install qemu-user"),
    ("unblob",      "recursive firmware extraction with structured reports", "firmware_reverse_safe extract",
     "apt install unblob or install unblob in an isolated environment"),
    ("binwalk",     "firmware signature scan and extraction",  "firmware_reverse_safe extract",
     "python3 -m pip install binwalk or apt install binwalk"),
    ("emba",        "EMBA firmware analysis and SBOM reporting", "firmware_tooling_extended",
     "clone EMBA in an isolated VM, run its installer, then set EMBA_HOME or --emba-path"),
    ("rsf.py",      "RouterSploit local module catalog (no active modules run by TBHM)", "firmware_tooling_extended",
     "clone RouterSploit and set ROUTERSPLOIT_HOME or --routersploit-root"),
    ("unsquashfs",  "SquashFS root filesystem extraction",     "firmware_reverse_safe extract",
     "apt install squashfs-tools"),
    ("sasquatch",   "vendor-modified SquashFS extraction",     "firmware_reverse_safe fallback",
     "build from github.com/devttys0/sasquatch"),
    ("checksec",    "reference binary hardening cross-check",   "firmware_reverse_safe (built-in parser also covers this)",
     "apt install checksec"),
    ("qemu-mipsel-static", "little-endian MIPS user emulation", "external sandbox workflow",
     "apt install qemu-user-static"),
    ("qemu-mips-static",   "big-endian MIPS user emulation",    "external sandbox workflow",
     "apt install qemu-user-static"),
]


def run(ctx):
    lines = []
    lines.append("=" * 70)
    lines.append("TBHM DIAGNOSTIC REPORT")
    lines.append("=" * 70)
    lines.append("")

    # 1. Tool availability
    installed = []
    missing = []
    for tool, desc, where, hint in TOOL_CHECKS:
        path = shutil.which(tool)
        if path:
            ver = _get_version(tool)
            installed.append((tool, desc, where, path, ver))
        else:
            missing.append((tool, desc, where, hint))

    lines.append(f"## TOOLS: {len(installed)} installed, {len(missing)} missing")
    lines.append("")
    lines.append("### ✅ Installed")
    for tool, desc, where, path, ver in installed:
        lines.append(f"  {tool:<14}  {ver:<20}  used by: {where}")
    lines.append("")

    if missing:
        lines.append("### ❌ Missing — these phases will skip or degrade")
        for tool, desc, where, hint in missing:
            lines.append(f"  {tool:<14}  ({desc})")
            lines.append(f"                 used by: {where}")
            lines.append(f"                 install: {hint}")
        lines.append("")

    # v3.9: local model hardware/readiness. Detection is read-only and does not
    # install drivers, change GPU settings, or download a model.
    hw = detect_hardware()
    lines.append("## LOCAL LLM HARDWARE PROFILE")
    lines.append(f"  RAM:             {hw.get('ram_gb', 0)} GB")
    lines.append(f"  NVIDIA GPUs:     {json.dumps(hw.get('nvidia_gpus', []), ensure_ascii=False)}")
    lines.append(f"  Recommended:     {hw.get('recommended_model_size')} {hw.get('recommended_quantization')}")
    lines.append(f"  Context/parallel:{hw.get('recommended_context')} / {hw.get('recommended_parallel_requests')}")
    lines.append(f"  Inference mode:  {hw.get('inference_mode')}")
    if getattr(ctx.args, "local_llm", False):
        try:
            from core.llm_local import runtime_from_args
            runtime = getattr(ctx, "local_llm_runtime", None) or runtime_from_args(ctx.args)
            ctx.local_llm_runtime = runtime
            ready, detail = runtime.client.available()
            lines.append(f"  Ollama/model:    {'READY' if ready else 'NOT READY'} — {detail}")
        except Exception as exc:
            lines.append(f"  Ollama/model:    NOT READY — {exc}")
    else:
        lines.append("  Ollama/model:    not checked (enable --local-llm)")
    lines.append("")

    # 2. nuclei template count
    if shutil.which("nuclei"):
        template_count = bootstrap.nuclei_template_count()
        template_root = bootstrap.nuclei_templates_root()
        # Only inspect metadata. Template builders/setup must never execute in diagnostics.
        custom_root = getattr(bootstrap, 'CUSTOM_TEMPLATE_DIR', None)
        custom_count = sum(1 for _ in custom_root.rglob('*.yaml')) if custom_root and custom_root.is_dir() else 0
        custom_info = {'count': custom_count}
        lines.append(f"## NUCLEI TEMPLATES: {template_count} official templates loaded")
        lines.append(f"  official root: {template_root or 'not found'}")
        lines.append(f"  TBHM custom  : {custom_info.get('count', 0)} bundled templates")
        if template_count <= 0:
            lines.append("  ❌ No official templates! Run: ./tbhm.py --setup or nuclei -update-templates")
        elif template_count < 1000:
            lines.append(f"  ⚠️  Only {template_count} official templates. Expected 5000+.")
            lines.append("     Run: ./tbhm.py --setup or nuclei -update-templates")
        else:
            lines.append(f"  ✅ Healthy official template count ({template_count})")
        lines.append("")

    # 3. subfinder provider config
    if shutil.which("subfinder"):
        provider_config = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
        if provider_config.exists():
            content = provider_config.read_text()
            api_keys_set = sum(1 for line in content.split("\n")
                              if ":" in line and not line.strip().startswith("#")
                              and len(line.split(":", 1)[1].strip()) > 5)
            lines.append(f"## SUBFINDER PROVIDERS: {api_keys_set} API keys configured")
            if api_keys_set < 3:
                lines.append(f"  ⚠️  Only {api_keys_set} API keys. Subdomain enum will be shallow.")
                lines.append(f"     Add keys for: CHAOS, GITHUB_TOKEN, SHODAN, VirusTotal, Censys")
                lines.append(f"     Edit: {provider_config}")
            else:
                lines.append(f"  ✅ Multi-source enum will work")
        else:
            lines.append(f"## SUBFINDER PROVIDERS: no provider-config.yaml")
            lines.append(f"  ⚠️  Only passive sources (crt.sh, AlienVault) will work.")
            lines.append(f"     Create: {provider_config}")
            lines.append(f"     Add CHAOS_KEY, GITHUB_TOKEN, SHODAN at minimum.")
        lines.append("")

    # 4. SecLists wordlists
    seclists_paths = [
        Path("/usr/share/seclists"),
        Path.home() / "SecLists",
        Path("/opt/SecLists"),
    ]
    seclists_found = next((p for p in seclists_paths if p.exists()), None)
    if seclists_found:
        lines.append(f"## SECLISTS: {seclists_found} ✅")
    else:
        lines.append("## SECLISTS: ❌ not found")
        lines.append("  Without SecLists, content_discovery uses bundled wordlists only.")
        lines.append("  Install: git clone https://github.com/danielmiessler/SecLists "
                     "/usr/share/seclists")
    lines.append("")

    # 5. interactsh (OOB)
    if shutil.which("interactsh-client"):
        lines.append("## OOB INTERACTSH: ✅ installed (SSRF detection enabled)")
    else:
        lines.append("## OOB INTERACTSH: ❌ not installed")
        lines.append("  Without interactsh, OOB SSRF / blind SSTI tests are degraded.")
        lines.append("  Install: go install -v "
                     "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
    lines.append("")

    # 6. Profile + intensity summary
    profile_name = (ctx.profile or {}).get("name", "?") if isinstance(ctx.profile, dict) \
                   else getattr(ctx.profile, "name", "?")
    intensity = getattr(ctx.args, "intensity", "standard")
    lines.append(f"## RUN CONFIG")
    lines.append(f"  profile:   {profile_name}")
    lines.append(f"  intensity: {intensity}")
    lines.append(f"  targets:   {len(ctx.targets)} ({', '.join(ctx.targets[:3])})")
    if intensity == "quick":
        lines.append(f"  ⚠️  --quick severely limits what phases run. For full coverage use --standard or --deep.")
    lines.append("")

    # 7. Verdict
    critical_missing = [t for t, d, w, h in missing
                         if t in ("nuclei", "subfinder", "httpx", "curl")]
    lines.append("=" * 70)
    if critical_missing:
        lines.append(f"⚠️  VERDICT: scan will be DEGRADED ({len(critical_missing)} critical tools missing).")
    elif missing:
        lines.append(f"✅ VERDICT: scan will run, but {len(missing)} optional tools missing.")
    else:
        lines.append("⚠️  VERDICT: tools detected; operational readiness and coverage unverified.")
    lines.append("=" * 70)

    report = "\n".join(lines)
    # Write file
    out_path = ctx.output / "diagnostics.txt"
    out_path.write_text(report)

    # Also log the summary
    ctx.log("INFO", "diagnostics",
            f"━━━ Pre-scan diagnostic written to {out_path.name} ━━━")
    for line in lines:
        if line.strip():
            ctx.log("INFO", "diagnostics", "  " + line[:200])

    # Save as a finding so it shows in reports
    ctx.save_finding({
        "phase": "diagnostics", "severity": "INFO", "confidence": "HIGH",
        "title": f"Pre-scan tool diagnostic: {len(installed)} installed, {len(missing)} missing",
        "target": ctx.targets[0] if ctx.targets else "",
        "url": "", "method": "",
        "evidence": f"See diagnostics.txt for full breakdown. "
                    f"Critical-missing: {[t for t,d,w,h in missing if t in ('nuclei','subfinder','httpx')]}",
        "description": (
            "If the scan misses findings you expected, check this diagnostic. "
            "Common cause of 'tool found nothing': nuclei templates not downloaded, "
            "subfinder has no API keys, or critical scanners (nuclei/dalfox/wpscan) "
            "aren't installed."
        ),
        "impact": "Informational — affects coverage of all subsequent phases.",
        "remediation": "Run ./install.sh to install missing tools. "
                      "Run 'nuclei -update-templates' to populate templates.",
        "mrs_score": 25,
    })


def _get_version(tool: str) -> str:
    """Presence-only result: unvetted wrappers may install, download or request sudo.

    Never execute arbitrary binaries or version flags as a diagnostic side effect.
    A dedicated adapter readiness test is required for capability verification.
    """
    return "detected / not probed" if shutil.which(tool) else "not installed"
