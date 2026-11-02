"""Bug-bounty identity, request, workflow and policy workspace.

This phase prepares redacted request models and versioned security-invariant
assertions. It never sends a request. A later approved executor can consume only
queue rows marked READY after scope, method, identity, request and assertion
checks all pass.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from core import program_policy
from core.request_model import import_har

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


def _load(path: str | None):
    if not path:
        return {}
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    if yaml is None:
        raise ValueError("PyYAML is required for YAML workspace files")
    return yaml.safe_load(text) or {}


def _hash(path: str | None) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else ""
    except Exception:
        return ""


def _assertion(test: dict, workflow: dict) -> tuple[dict, list[str]]:
    raw = test.get("assertion") if isinstance(test.get("assertion"), dict) else {}
    assertion = {
        "schema_version": str(raw.get("schema_version") or "1"),
        "test_id": str(raw.get("test_id") or test.get("test_id") or test.get("id") or ""),
        "invariant": str(raw.get("invariant") or test.get("expected_invariant") or workflow.get("invariant") or ""),
        "failure_conditions": raw.get("failure_conditions") or test.get("failure_conditions") or [],
        "negative_control_conditions": raw.get("negative_control_conditions") or test.get("negative_control_conditions") or [],
    }
    errors = []
    if not assertion["test_id"]:
        errors.append("test_id missing")
    if not assertion["invariant"]:
        errors.append("invariant missing")
    if not isinstance(assertion["failure_conditions"], list) or not assertion["failure_conditions"]:
        errors.append("failure_conditions missing")
    if not isinstance(assertion["negative_control_conditions"], list) or not assertion["negative_control_conditions"]:
        errors.append("negative_control_conditions missing")
    return assertion, errors


def run(ctx):
    out = ctx.output / "evidence" / "bug_bounty_workspace"
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "policy": {"loaded": False}, "identities": 0, "workflows": 0,
        "requests": 0, "validation_queue": 0, "ready": 0, "blocked": 0,
        "boundary": "Workspace preparation only; no active request is sent and no credentials are stored.",
    }

    policy = getattr(ctx, "program_policy", None) or {}
    policy_path = getattr(ctx.args, "program_policy", None)
    if policy_path and not policy:
        try:
            policy = program_policy.load(policy_path)
            ctx.storage.save_program_policy(policy, _hash(policy_path))
            ctx.program_policy = policy
        except Exception as exc:
            summary["policy"] = {"loaded": False, "error": str(exc)}
            ctx.log("WARN", "bug_bounty_workspace", f"program policy rejected: {exc}")
    if policy:
        summary["policy"] = program_policy.summary(policy)
        (out / "program_policy.normalized.json").write_text(json.dumps(policy, indent=2, default=str))

    identities_doc = _load(getattr(ctx.args, "identity_plan", None)) if getattr(ctx.args, "identity_plan", None) else {}
    identities = identities_doc if isinstance(identities_doc, list) else identities_doc.get("identities", []) if isinstance(identities_doc, dict) else []
    normalized_identities = []
    for row in identities[:100]:
        if not isinstance(row, dict) or not (row.get("identity_id") or row.get("id")):
            continue
        clean = {
            "identity_id": str(row.get("identity_id") or row.get("id")),
            "role": str(row.get("role") or ""),
            "tenant": str(row.get("tenant") or ""),
            "session_label": str(row.get("session_label") or ""),
            "session_provider_ref": str(row.get("session_provider_ref") or ""),
            "metadata": {k: v for k, v in (row.get("metadata") or {}).items()
                         if str(k).lower() not in {"password", "token", "cookie", "authorization", "secret"}},
        }
        ctx.storage.save_identity_context(clean)
        normalized_identities.append(clean)
    identity_index = {x["identity_id"]: x for x in normalized_identities}
    summary["identities"] = len(normalized_identities)
    (out / "identity_contexts.json").write_text(json.dumps(normalized_identities, indent=2))

    requests = []
    if getattr(ctx.args, "session_har", None):
        try:
            requests = import_har(ctx.args.session_har, max_entries=int(getattr(ctx.args, "workspace_max_requests", 5000) or 5000))
        except Exception as exc:
            ctx.log("WARN", "bug_bounty_workspace", f"HAR import failed: {exc}")
    request_index = {x["request_id"]: x for x in requests}
    summary["requests"] = len(requests)
    with (out / "redacted_requests.jsonl").open("w", encoding="utf-8") as handle:
        for row in requests:
            handle.write(json.dumps(row, default=str) + "\n")

    workflows_doc = _load(getattr(ctx.args, "workflow_plan", None)) if getattr(ctx.args, "workflow_plan", None) else {}
    workflows = workflows_doc if isinstance(workflows_doc, list) else workflows_doc.get("workflows", []) if isinstance(workflows_doc, dict) else []
    normalized_workflows = []
    validation_queue = []
    for row in workflows[:500]:
        if not isinstance(row, dict) or not row.get("invariant"):
            continue
        workflow_id = str(row.get("workflow_id") or row.get("id") or f"workflow-{len(normalized_workflows)+1}")
        clean = {**row, "workflow_id": workflow_id, "name": str(row.get("name") or workflow_id),
                 "invariant": str(row.get("invariant"))}
        ctx.storage.save_workflow_model(clean)
        normalized_workflows.append(clean)
        for test in row.get("tests", []) if isinstance(row.get("tests"), list) else []:
            if not isinstance(test, dict):
                continue
            assertion, errors = _assertion(test, clean)
            identity_id = str(test.get("identity_id") or "")
            request_id = str(test.get("request_id") or "")
            request = request_index.get(request_id)
            identity = identity_index.get(identity_id)
            if not identity:
                errors.append("identity_id is not present in identity plan")
            if not request:
                errors.append("request_id is not present in imported request workspace")
            scope = program_policy.evaluate_asset(policy, request.get("url", "")) if policy and request else {
                "decision": "unclear", "reason": "reviewed program policy or request missing", "policy_id": ""
            }
            action = program_policy.evaluate_action(
                policy, str(test.get("action") or "workflow_test"), method=request.get("method", "") if request else ""
            ) if policy else {"allowed": False, "reason": "reviewed program policy missing"}
            if scope.get("decision") != "in_scope":
                errors.append(f"scope: {scope.get('decision')} ({scope.get('reason')})")
            if not action.get("allowed"):
                errors.append(f"policy action: {action.get('reason')}")
            if identity and not identity.get("session_provider_ref"):
                errors.append("identity session_provider_ref missing")
            status = "READY_FOR_APPROVED_EXECUTOR" if not errors else "BLOCKED"
            validation_queue.append({
                "workflow_id": workflow_id,
                "test_id": assertion["test_id"],
                "identity_id": identity_id,
                "request_id": request_id,
                "expected_invariant": assertion["invariant"],
                "assertion": assertion,
                "scope_decision": scope,
                "policy_action": action,
                "status": status,
                "blocking_reasons": errors,
            })
    summary["workflows"] = len(normalized_workflows)
    summary["validation_queue"] = len(validation_queue)
    summary["ready"] = sum(1 for x in validation_queue if x["status"] == "READY_FOR_APPROVED_EXECUTOR")
    summary["blocked"] = len(validation_queue) - summary["ready"]
    (out / "workflow_models.json").write_text(json.dumps(normalized_workflows, indent=2, default=str))
    with (out / "workflow_validation_queue.jsonl").open("w", encoding="utf-8") as handle:
        for row in validation_queue:
            handle.write(json.dumps(row, default=str) + "\n")
    with (out / "workflow_validation_queue.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["workflow_id", "test_id", "identity_id", "request_id", "expected_invariant", "status", "blocking_reasons"]
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in validation_queue:
            writer.writerow({**row, "blocking_reasons": "; ".join(row["blocking_reasons"])})

    (out / "workspace_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    ctx.phase_state["bug_bounty_workspace"] = summary
    ctx.log("OK", "bug_bounty_workspace",
            f"policy={summary['policy'].get('loaded', False)} identities={summary['identities']} "
            f"workflows={summary['workflows']} requests={summary['requests']} ready={summary['ready']} blocked={summary['blocked']}")
