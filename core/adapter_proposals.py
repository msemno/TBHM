"""Proposal-only integration adapter generator."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

NAME=re.compile(r"^[A-Za-z0-9_.+ -]{2,80}$")
EXEC=re.compile(r"^[A-Za-z0-9_.+-]{1,80}$")


def generate(tool_definition: dict) -> dict:
    if not isinstance(tool_definition,dict): raise ValueError("tool definition must be an object")
    name=str(tool_definition.get("name") or "").strip(); executable=str(tool_definition.get("executable") or "").strip()
    if not NAME.fullmatch(name): raise ValueError("invalid tool name")
    if executable and not EXEC.fullmatch(executable): raise ValueError("invalid executable name")
    modes={"json","jsonl","sarif","csv","text"}; formats=[str(x).lower() for x in tool_definition.get("output_formats",[]) if str(x).lower() in modes]
    risk=str(tool_definition.get("risk") or "medium").lower()
    if risk not in {"low","medium","high","critical"}: raise ValueError("invalid risk")
    requested_command=tool_definition.get("command_template")
    command_mapping={"executable":executable,"arguments":["<validated-arguments-only>"],"shell":False,"activation":"disabled_pending_human_review"}
    if requested_command: command_mapping["operator_supplied_template_hash"]=hashlib.sha256(str(requested_command).encode()).hexdigest()
    proposal={"proposal_id":"adapter-proposal-"+hashlib.sha256(json.dumps(tool_definition,sort_keys=True,default=str).encode()).hexdigest()[:20],"name":name,"status":"UNAPPROVED_PROPOSAL","implementation_state":"proposal_only","generated_at":datetime.now(timezone.utc).isoformat(),"proposed_adapter_metadata":{"id":re.sub(r"[^a-z0-9]+","-",name.lower()).strip("-"),"name":name,"risk":risk,"integration_mode":"proposal_only","executable":executable},"proposed_command_mapping":command_mapping,"proposed_input_schema":tool_definition.get("input_schema") or {"type":"object","additionalProperties":False},"proposed_output_parser":{"formats":formats or ["json"],"normalizer":"core.scanner_normalizer.parse_file","unknown_fields":"preserve under provenance/unmapped"},"proposed_tests":["reject shell metacharacters and arbitrary executables","fixture parse for each declared format","malformed input does not crash","missing executable is reported as unavailable","output provenance and deduplication are preserved"],"proposed_documentation":["installation is operator-managed","capability remains disabled until code review and tests pass","risk and approval requirements must be documented"],"risk_classification":{"risk":risk,"requires_security_review":True,"approval_required":risk in {"high","critical"}},"activation":{"approved":False,"automatic_install":False,"automatic_execution":False}}
    return proposal
