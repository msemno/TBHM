# Integrated Local LLM and Authorized Exercise Evidence — v3.9.1

## Local LLM inside TBHM

The integration is part of the orchestrator, storage-enrichment flow, and report pipeline. The model process remains local through Ollama because a 4B model file is too large to redistribute inside the TBHM ZIP and may have separate licensing requirements.

Recommended starting configuration for the stated ASUS TUF Gaming A16 running Kali Linux with 16 GB RAM and 8 GB NVIDIA VRAM:

- model size: 4B
- quantization: Q4_K_M
- context: 4096 tokens
- parallel requests: 1
- scanner execution: sequential while the model is active
- inference: GPU-preferred with CPU fallback

Readiness:

```bash
./tbhm.py --local-llm-status
```

Pull an Ollama registry model explicitly:

```bash
./tbhm.py --local-llm-setup --local-llm-model MODEL_NAME
```

Create the local alias from an operator-approved Modelfile and GGUF:

```bash
./tbhm.py --local-llm-setup \
  --local-llm-model qwen3-cybersec:4b \
  --local-llm-modelfile models/Modelfile.qwen3-cybersec.example
```

Use it during a run:

```bash
./tbhm.py -d example.internal -y --local-llm
```

The report phase automatically performs enrichment when the flag is enabled, even if a custom phase list only contains `report`.

## Authorized exercise evidence

Import evidence from a separately approved exercise:

```bash
./tbhm.py -d corp.internal -y \
  --engagement-evidence ./approved-exercise-evidence \
  --local-llm \
  --phases engagement_evidence_review,report
```

The phase records file hashes, sanitizes operational content, creates lead-only observations, maps MITRE ATT&CK categories, and lets the local model add defensive metadata and remediation.

## Instructor simulation

```bash
./tbhm.py -d training.local -y \
  --exercise-simulation \
  --exercise-scenario ad-domain-compromise \
  --local-llm \
  --phases engagement_evidence_review,report
```

This path produces synthetic exercise cards only. It performs no network action and does not generate operational commands.

## Boundary

The evidence phase does not execute the activities represented by imported artifacts. It does not capture credentials, recover passwords, request tickets, reuse hashes, execute commands remotely, extract directory secrets, create shells, establish persistence, evade EDR, or disable TBHM safety controls.
