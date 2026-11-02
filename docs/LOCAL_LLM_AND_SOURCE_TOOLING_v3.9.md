# Local LLM and Source-Security Tooling — v3.9-safe

## Intended machine profile

The local integration is sized for a laptop in the class of an ASUS TUF Gaming A16 with 16 GB system RAM and an NVIDIA GPU with 8 GB VRAM. TBHM detects the machine at runtime using `psutil` and `nvidia-smi`; it does not change driver, CUDA, power, or GPU settings.

Recommended starting point:

- Model size: 4B
- Quantization: Q4_K_M
- Context: 4096 tokens; reduce to 2048 if memory pressure or extraction quality is unstable
- Parallel model requests: 1
- Runtime: Ollama on loopback
- Cloud fallback: none

Q8 can be tried but leaves less VRAM/RAM headroom for Kali, scanners, browser processes, and report generation. A 32B reasoning model is not a practical local default for 8 GB VRAM and 16 GB RAM.

The referenced `DexopT/Qwen3-4B-Cybersecurity` model card reports 1,284,369 fine-tuning samples, not 1.8 million. Review the current upstream model card and license before use. The example model name `qwen3-cybersec:4b` is a local Ollama alias chosen by the operator; TBHM does not download or redistribute model weights.

## Model import

1. Install Ollama manually, or run:

```bash
INSTALL_OLLAMA=1 ./install.sh
```

2. Obtain an approved GGUF from the upstream publisher and verify its checksum/license.
3. Copy `models/Modelfile.qwen3-cybersec.example` to a working directory and replace the `FROM` path with the absolute GGUF path.
4. Create the local alias:

```bash
ollama create qwen3-cybersec:4b -f ./Modelfile
ollama list
```

TBHM never downloads the model automatically.

## Local triage usage

```bash
./tbhm.py -d source-analysis.local -y \
  --code-dir /path/to/source \
  --code-security-tooling \
  --code-security-tools bandit,semgrep,gitleaks,trivy,checkov \
  --local-llm \
  --local-llm-model qwen3-cybersec:4b \
  --phases code_security_tooling,verify,local_llm_triage,report
```

The model receives redacted, bounded excerpts from already stored findings. It may fill empty CWE/CVSS metadata and attach enrichment under `extra_json`, but it cannot promote a lead, overwrite existing metadata, call scanners, or execute commands.

## s0-cli integration

```bash
./tbhm.py -d source-analysis.local -y \
  --code-dir /path/to/source \
  --source-orchestration \
  --source-orchestration-tools s0 \
  --phases source_orchestration_tooling,verify,local_llm_triage,report \
  --local-llm
```

TBHM forces s0-cli to run with `--no-llm` and SARIF output. This prevents a second model/provider from receiving the repository and keeps all optional model enrichment in the local TBHM phase.

When s0 is installed as a local `uv` project rather than a command on `PATH`:

```bash
./tbhm.py -d source-analysis.local -y \
  --code-dir /path/to/source \
  --source-orchestration --s0-dir /path/to/s0-cli
```

## Importing other orchestrators

Argus, Mega-Linter, SonarQube, CodeQL, and DefectDojo remain import-only because their runtime, containers, server APIs, authentication, and optional AI/sandbox behavior vary by version and deployment.

```bash
./tbhm.py -d source-analysis.local -y \
  --source-orchestration-results /path/to/results \
  --phases source_orchestration_tooling,verify,local_llm_triage,report \
  --local-llm
```

All imported records are scanner observations/leads until separately verified.

## Expanded local scanner examples

```bash
INSTALL_CODE_SECURITY=1 ./install.sh

./tbhm.py -d source-analysis.local -y \
  --code-dir /path/to/source \
  --code-security-tooling \
  --code-security-tools bandit,njsscan,gitleaks,trivy,grype,checkov,terrascan,tfsec,semgrep,ruff,gosec,eslint,trufflehog,detect-secrets,syft,safety,dependency-check,hadolint \
  --phases code_security_tooling,verify,local_llm_triage,report \
  --local-llm
```

Tools that require a server, proprietary account, complex build database, or cloud upload are normalized through `--code-security-results` instead of being launched automatically.

## Security boundaries

- No model tool calling.
- No model-generated scanner payloads or shell commands.
- Loopback-only endpoint; no cloud fallback, proxy routing, or redirect following.
- No repository changes.
- TruffleHog verification is disabled in this phase.
- Secrets are redacted before local model input.
- Scanner and model conclusions never equal confirmation by themselves.
