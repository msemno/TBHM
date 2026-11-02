"""Portable AI-plane home directory.

Everything the local AI co-pilot learns lives OUTSIDE the TBHM tree, under a
single directory resolved here. That directory survives ZIP replacement and can
be copied verbatim to another laptop. The tool code (this package) travels with
the ZIP; the *state* (database, index, proposals, audit) travels in TBHM_AI_HOME.

Resolution order:
  1. $TBHM_AI_HOME                       (explicit, highest priority)
  2. $XDG_DATA_HOME/tbhm-ai              (if XDG_DATA_HOME set)
  3. ~/.local/share/tbhm-ai             (default)

Never store anything durable inside TBHM-v3/, results/, or an extraction dir.
A new ZIP could overwrite or omit those; this directory is deliberately separate.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

LAYOUT = (
    "config",
    "database",
    "knowledge/objects",
    "knowledge/imported-resources",
    "knowledge/approved-lessons",
    "indexes",
    "models",
    "audit",
    "proposals/pending",
    "proposals/accepted",
    "proposals/rejected",
    "backups",
    "migrations",
    "ollama-models",  # only used for optional offline model migration
)

_SCHEMA_VERSION = 1


def resolve_home(explicit: str | None = None) -> Path:
    """Return the AI-plane home path (does not create it)."""
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("TBHM_AI_HOME")
    if env:
        return Path(env).expanduser().resolve()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return (Path(xdg).expanduser() / "tbhm-ai").resolve()
    return (Path.home() / ".local" / "share" / "tbhm-ai").resolve()


@dataclass
class AIHome:
    root: Path

    # --- canonical paths -----------------------------------------------------
    @property
    def config_dir(self) -> Path: return self.root / "config"
    @property
    def db_path(self) -> Path: return self.root / "database" / "memory.sqlite3"
    @property
    def objects_dir(self) -> Path: return self.root / "knowledge" / "objects"
    @property
    def resources_dir(self) -> Path: return self.root / "knowledge" / "imported-resources"
    @property
    def lessons_dir(self) -> Path: return self.root / "knowledge" / "approved-lessons"
    @property
    def index_path(self) -> Path: return self.root / "indexes" / "vectors.npz"
    @property
    def index_manifest(self) -> Path: return self.root / "indexes" / "vector-manifest.json"
    @property
    def model_lock(self) -> Path: return self.root / "models" / "model-lock.json"
    @property
    def modelfile(self) -> Path: return self.root / "models" / "Modelfile.tbhm"
    @property
    def audit_events(self) -> Path: return self.root / "audit" / "ai-events.jsonl"
    @property
    def decisions_log(self) -> Path: return self.root / "audit" / "decisions.jsonl"
    @property
    def hash_chain(self) -> Path: return self.root / "audit" / "hash-chain.jsonl"
    @property
    def proposals_pending(self) -> Path: return self.root / "proposals" / "pending"
    @property
    def proposals_accepted(self) -> Path: return self.root / "proposals" / "accepted"
    @property
    def proposals_rejected(self) -> Path: return self.root / "proposals" / "rejected"
    @property
    def backups_dir(self) -> Path: return self.root / "backups"
    @property
    def ai_config(self) -> Path: return self.config_dir / "ai.yaml"

    def ensure(self) -> "AIHome":
        """Create the full directory layout and a stamp file. Idempotent."""
        for rel in LAYOUT:
            (self.root / rel).mkdir(parents=True, exist_ok=True)
        stamp = self.root / ".tbhm-ai-home"
        if not stamp.exists():
            stamp.write_text(json.dumps({
                "schema": _SCHEMA_VERSION,
                "note": "TBHM AI-plane home. Portable. Copy this whole directory to migrate.",
            }, indent=2), encoding="utf-8")
        return self

    def exists(self) -> bool:
        return (self.root / ".tbhm-ai-home").exists()


def get(explicit: str | None = None, create: bool = False) -> AIHome:
    home = AIHome(resolve_home(explicit))
    if create:
        home.ensure()
    return home
