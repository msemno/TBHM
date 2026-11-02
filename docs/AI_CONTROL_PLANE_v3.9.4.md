# AI Control Plane (v3.9.4) — portable, non-authoritative co-pilot

The co-pilot is a **separate control plane**, not another scan phase and not a
self-modifying agent. It observes TBHM through structured events, retrieves
TBHM's own source to ground its reasoning, and **proposes** improvements it never
applies. Its safety envelope is the same loopback-only, redirect-rejecting,
secret-redacting boundary the existing local-LLM code already enforces.

```
 TBHM source ──delta indexer──▶ SQLite (source of truth) ──▶ rebuildable vector index
      │                               ▲                              │
 phase events ──sanitizer(T0..T4)──────┘                       retrieval
      │                                                              ▼
      └───────────────────────────────────────────────▶ Advisor LLM (analysis + proposals only)
                                                                     │  strict JSON
                                                                     ▼
                                                        Policy / approval gate (no auto-exec)
                                                                     │ approved
                                                                     ▼
                                                   Git branch → tests → review → merge (you do this)
```

## Where the memory lives (and why it is portable)

Everything the co-pilot learns lives in **one directory outside the tool tree**:

```
$TBHM_AI_HOME            # default: ~/.local/share/tbhm-ai
├── database/memory.sqlite3     # AUTHORITATIVE. runs, events, findings, lessons, proposals, knowledge
├── indexes/vectors.npz         # rebuildable cache (regenerated from the DB)
├── knowledge/                  # ingested resources/notes + objects
├── models/model-lock.json      # exact advisor + embedding model names to re-pull
├── proposals/{pending,accepted,rejected}
├── audit/hash-chain.jsonl      # tamper-evident decision trail
└── backups/
```

The tool code (`core/ai_plane/`) ships **inside** the ZIP; the *state* ships in
`$TBHM_AI_HOME`. Replacing the ZIP never touches your memory. SQLite is the
source of truth; if the vector index is ever lost or an upgrade makes it
incompatible, it is rebuilt from the chunk table — you never lose knowledge to a
corrupt index.

## First run (once, during/after install)

```bash
export TBHM_AI_HOME="$HOME/.local/share/tbhm-ai"
# with Ollama + models:
./tbhm.py --ai-init --ai-advisor-model qwen3-cybersec:4b --ai-embedding-model nomic-embed-text
# or index/DB only, pull models later:
./tbhm.py --ai-init --ai-no-pull

# or fold it into the installer:
INSTALL_OLLAMA=1 INSTALL_AI=1 ./install.sh
```

`--ai-init` creates the home, initializes the DB, records + optionally pulls the
models, indexes the whole tool (≈200 files → ≈1500 chunks), and writes
`model-lock.json`.

## The workflows you asked for

**After any code change / new version of the tool**
```bash
./tbhm.py --ai-sync-tool        # delta only: re-chunks/re-embeds just what changed
./tbhm.py --ai-review-delta     # same, plus an advisory review of the change (needs model)
```

**Move to a new laptop, or drop in a new ZIP**
```bash
# 1. copy the portable home across (this is your whole memory):
#    scp -r ~/.local/share/tbhm-ai  newbox:~/.local/share/tbhm-ai
# 2. unzip the new TBHM, then:
export TBHM_AI_HOME="$HOME/.local/share/tbhm-ai"
./tbhm.py --ai-migrate          # migrates schema + resyncs source delta to the new tree
# 3. re-pull the models named in model-lock.json (weights are not copied):
#    ollama pull qwen3-cybersec:4b ; ollama pull nomic-embed-text
./tbhm.py --ai-doctor           # verify DB, index, model, source-sync, audit
```

**Back up / restore the memory**
```bash
./tbhm.py --ai-backup                       # VACUUM INTO snapshot + tar.zst (weights excluded)
./tbhm.py --ai-restore /path/to/tbhm-ai-backup-YYYYMMDD-HHMMSS.tar.zst
```

**Teach it new ideas / tools / methodologies (no code change happens)**
```bash
./tbhm.py --ai-ingest-resource ~/notes/new-re-methodology.pdf
./tbhm.py --ai-ingest-note      ~/notes/new-tool.md
./tbhm.py --ai-ingest-folder    ~/resources/
```
Ingestion quarantines the file, scrubs secrets/PII, chunks it into knowledge, and
tells you which TBHM components it relates to. It does **not** modify any phase.
Any actual code change must go through `--ai-review-delta` → proposals.

**Use it during a scan**
```bash
./tbhm.py -d target --ai-observe            # records events, writes llm_analysis/AI_PLANE_ANALYSIS.md
```

**Governance**
```bash
./tbhm.py --ai-proposals                    # list pending change proposals
./tbhm.py --ai-approve AI-PROP-XXXXXXXX      # archive as accepted (does NOT auto-apply)
./tbhm.py --ai-reject  AI-PROP-XXXXXXXX
./tbhm.py --ai-verify-audit                  # verify the hash-chained decision trail
```

## Trust model

Every input is tagged T0–T4. T0 = hard-coded safety policy; T1 = TBHM code/docs;
T2 = approved external resources; T3 = scanner output; T4 = target-controlled
responses. T3/T4 content is fenced as untrusted data before it reaches the model
— usable as evidence, never as instructions, never able to change the task,
output format, or safety rules. This is the defense against prompt injection via
the knowledge channel.

## What it cannot do

It cannot execute commands, call tools, run scans, mutate a finding's
severity/confirmation, change scope, or write to the tool tree. It analyzes and
proposes. Approval and application remain a deliberate human git action.

## Models (16 GB RAM / 8 GB VRAM class)

Advisor `qwen3-cybersec:4b` (Q4_K_M), embeddings `nomic-embed-text`, context
4096 (≤8192 after testing), parallel requests 1, sequential execution. Do not run
the model concurrently with Ghidra/angr/heavy scanners. If no embedding model is
present, indexing/retrieval still work via a deterministic fallback (flagged in
the index manifest as `embedding_mode: fallback`) so the plane never hard-blocks.
