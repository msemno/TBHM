"""Generate a local, non-executing MCP capability manifest.

The manifest is a design/interoperability artifact. It does not start a server
and does not grant the AI permission to call operator tools.
"""
from __future__ import annotations


def build(*, phases: list[str], tool_rows: list[dict]) -> dict:
    tools = []
    for row in tool_rows:
        mode = str(row.get("integration_mode") or "import_only")
        tools.append({
            "name": str(row.get("id") or row.get("name") or "tool"),
            "description": str(row.get("description") or "")[:300],
            "category": row.get("category"),
            "risk": row.get("risk"),
            "integration_mode": mode,
            "ai_callable": mode in {"feed", "library"} and str(row.get("risk")).lower() == "low",
            "requires_human_approval": mode in {"approval_cli", "approval_only", "commercial_import"},
            "input_trust": "T3-untrusted",
            "output_trust": "T3-untrusted",
        })
    return {
        "protocol": "MCP-compatible declarative manifest",
        "network_server_started": False,
        "phase_resources": [{"name": f"phase:{p}", "read_only": True, "ai_callable": False} for p in phases],
        "tool_resources": tools,
        "policy": {
            "default": "deny",
            "high_impact_execution": "human-approved external workflow only",
            "code_changes": "propose-and-approve only",
            "scope_changes": "forbidden to AI",
            "finding_status_changes": "forbidden to AI",
        },
    }
