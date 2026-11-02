"""Evidence-backed, read-only multi-provider cloud IAM graph analysis.

The analyzer accepts operator-supplied JSON only. It never authenticates, assumes
roles, creates credentials, changes policy, or asserts exploitability from a
permission name alone.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SENSITIVE = {
    "aws": {
        "iam:createaccesskey": ("can_create_key", "A principal may be able to create durable credentials for a target identity."),
        "iam:passrole": ("can_delegate", "A principal may be able to pass a role to a compatible service, subject to resource and service permissions."),
        "sts:assumerole": ("can_assume", "A principal may be able to assume a role when the trust policy and conditions permit it."),
        "iam:attachuserpolicy": ("can_modify", "A principal may be able to attach a managed policy to a user."),
        "iam:putuserpolicy": ("can_modify", "A principal may be able to write an inline user policy."),
        "iam:putrolepolicy": ("can_modify", "A principal may be able to write an inline role policy."),
        "lambda:createfunction": ("can_delegate", "Creating a function with a privileged execution role may form a privilege path when iam:PassRole and resource permissions are also effective."),
        "ec2:runinstances": ("can_delegate", "Launching compute with an instance profile may expose role permissions when pass-role, resource, and network prerequisites are met."),
    },
    "azure": {
        "application administrator": ("assigned_role", "The Application Administrator role can manage many application registrations and service principals, but effective impact depends on tenant configuration and target ownership."),
        "privileged role administrator": ("assigned_role", "The Privileged Role Administrator role can manage Microsoft Entra role assignments and related privileged-access settings within its effective scope."),
        "microsoft.authorization/roleassignments/write": ("can_modify", "The permission can create or modify Azure RBAC assignments within its effective scope."),
        "owner": ("assigned_role", "The Owner role grants broad resource control and role-assignment rights within its assigned scope."),
        "user access administrator": ("assigned_role", "The User Access Administrator role can manage user access to Azure resources within scope."),
    },
    "gcp": {
        "iam.serviceaccounts.createkey": ("can_create_key", "The permission can create a service-account key when organization policy and resource scope allow it."),
        "iam.serviceaccounts.actas": ("impersonates", "The permission may allow acting as a service account when combined with a compatible service or token permission."),
        "iam.serviceaccounttokencreator": ("impersonates", "The role may allow minting short-lived credentials for a service account within scope."),
        "resourcemanager.projects.setiampolicy": ("can_modify", "The permission can modify project IAM policy when conditions and organization policy permit it."),
        "roles/owner": ("assigned_role", "The Owner role grants broad project control, subject to organization policies and conditions."),
        "roles/editor": ("assigned_role", "The legacy Editor role grants broad modification permissions across many project resources; effective impact depends on organization policy, conditions, and service-account use."),
    },
}

PROVIDER_MARKERS = {
    "aws": ("amazon resource name", "arn:aws:", "assumerole", "aws"),
    "azure": ("microsoft.graph", "serviceprincipal", "roleassignment", "azure", "entra", "roledefinitionname"),
    "gcp": ("serviceaccount:", "roles/", "gcp", "googleapis.com", "bindings"),
}


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: list[dict] = field(default_factory=list)

    def add_node(self, provider: str, kind: str, name: str, *, source: str, attrs: dict | None = None) -> str:
        key = f"{provider}:{kind}:{name}".lower()
        uid = "node-" + hashlib.sha256(key.encode()).hexdigest()[:20]
        self.nodes.setdefault(uid, {"id": uid, "provider": provider, "kind": kind, "name": name, "attributes": attrs or {}, "sources": []})
        if source not in self.nodes[uid]["sources"]:
            self.nodes[uid]["sources"].append(source)
        return uid

    def add_edge(self, provider: str, source_id: str, target_id: str, relation: str, *, evidence: dict) -> str:
        basis = json.dumps([provider, source_id, target_id, relation, evidence.get("permission"), evidence.get("json_path")], separators=(",", ":"), sort_keys=True)
        uid = "edge-" + hashlib.sha256(basis.encode()).hexdigest()[:20]
        row = {"id": uid, "provider": provider, "source": source_id, "target": target_id, "relation": relation, "evidence": evidence}
        if not any(item["id"] == uid for item in self.edges):
            self.edges.append(row)
        return uid


def _walk(value):
    """v3.9.6 compatibility iterator returning dictionary keys and values."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)
    elif value is not None:
        yield str(value)


def _iter_strings(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _iter_strings(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_strings(item, f"{path}[{index}]")
    elif value is not None:
        yield path, str(value)


def _find_first(value: Any, keys: tuple[str, ...]) -> str:
    wanted = {key.lower() for key in keys}
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in wanted and isinstance(item, (str, int)) and str(item).strip():
                return str(item).strip()
        for item in value.values():
            found = _find_first(item, keys)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_first(item, keys)
            if found:
                return found
    return ""


def _provider_hints(path: Path, data: Any) -> set[str]:
    strings = [raw.lower() for _, raw in list(_iter_strings(data))[:100000]]
    text = (path.name.lower() + " " + " ".join(strings))
    hints = set()
    for provider, table in SENSITIVE.items():
        if any(permission in text or permission.replace(":", "*") in text for permission in table):
            hints.add(provider)
        elif any(marker in text for marker in PROVIDER_MARKERS[provider]):
            hints.add(provider)
    return hints


def _provider_hint(path: Path, data: Any) -> str:
    """Backward-compatible single-provider hint; multi-provider analysis uses all hints."""
    hints = _provider_hints(path, data)
    return next((provider for provider in ("aws", "azure", "gcp") if provider in hints), "generic")


def _principal_name(data: Any, source: Path, provider: str = "generic") -> str:
    keys = {
        "aws": ("UserName", "RoleName", "Arn", "Principal", "principal"),
        "azure": ("principalName", "userPrincipalName", "principalId", "assignee", "displayName"),
        "gcp": ("member", "email", "serviceAccount", "name"),
        "generic": ("UserName", "RoleName", "userPrincipalName", "principalName", "displayName", "email", "name", "member", "principalId", "principal"),
    }
    return _find_first(data, keys.get(provider, keys["generic"])) or source.stem


def _permissions(data: Any, provider: str) -> list[tuple[str, str]]:
    hits = []
    table = SENSITIVE.get(provider, {})
    for json_path, raw in _iter_strings(data):
        value = raw.lower().strip()
        normalized = value.replace("*", ":")
        for permission in table:
            wildcard = permission.replace(":", "*")
            if permission == value or permission in value or wildcard == value or wildcard in value or permission in normalized:
                hits.append((permission, json_path))
    seen = set()
    out = []
    for item in hits:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out[:10000]


def _azure_role_assignments(data: Any) -> list[tuple[str, str, str]]:
    out = []
    def walk(value):
        if isinstance(value, dict):
            role = str(value.get("roleDefinitionName") or value.get("roleName") or value.get("displayName") or "")
            principal = str(value.get("principalName") or value.get("userPrincipalName") or value.get("principalId") or value.get("assignee") or "")
            scope = str(value.get("scope") or value.get("resourceScope") or "tenant")
            if role and principal:
                out.append((principal, role, scope))
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(data)
    return out


def _gcp_bindings(data: Any) -> list[tuple[str, str]]:
    out = []
    def walk(value):
        if isinstance(value, dict):
            if isinstance(value.get("role"), str) and isinstance(value.get("members"), list):
                out.extend((str(member), str(value["role"])) for member in value["members"])
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(data)
    return out


def analyze(path: str | Path, *, max_files: int = 2000) -> dict:
    root = Path(path)
    files = [root] if root.is_file() else sorted((p for p in root.rglob("*.json") if p.is_file()), key=lambda p: p.as_posix()) if root.is_dir() else []
    graph = Graph()
    indicators = []
    malformed = []
    seen_indicators = set()

    def add_indicator(*, provider: str, principal: str, permission: str, relation: str, reason: str, source: Path, json_path: str, edge_id: str):
        key = (provider, principal.lower(), permission.lower(), source.name, json_path)
        if key in seen_indicators:
            return
        seen_indicators.add(key)
        indicators.append({
            "provider": provider,
            "principal": principal,
            "permission_or_role": permission,
            "relation": relation,
            "reason": reason,
            "source": source.name,
            "json_path": json_path,
            "edge_id": edge_id,
            "status": "POTENTIAL_PATH_REQUIRES_EFFECTIVE_SCOPE_TRUST_AND_CONDITION_CONTEXT",
            "legacy_status": "POTENTIAL_PATH_REQUIRES_GRAPH_CONTEXT",
            "prerequisites": [
                "permission or role is effective for the relevant resource",
                "trust, assignment, and conditional-access conditions permit the action",
                "organization policies, explicit denies, and compensating controls do not block it",
            ],
            "exploitability": "not asserted",
        })

    for source in files[:max_files]:
        try:
            data = json.loads(source.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            malformed.append({"source": str(source), "error": f"{type(exc).__name__}: {exc}"})
            continue

        structured_permissions = set()
        for principal_name, role, scope in _azure_role_assignments(data):
            provider = "azure"
            src = graph.add_node(provider, "service_principal_or_user", principal_name, source=source.name)
            dst = graph.add_node(provider, "role", role, source=source.name, attrs={"scope": scope})
            edge_id = graph.add_edge(provider, src, dst, "assigned_role", evidence={"source": source.name, "scope": scope, "json_path": "role_assignment", "permission": role.lower()})
            canonical = role.lower().strip()
            if canonical in SENSITIVE[provider]:
                relation, reason = SENSITIVE[provider][canonical]
                add_indicator(provider=provider, principal=principal_name, permission=canonical, relation=relation, reason=reason, source=source, json_path="role_assignment", edge_id=edge_id)
                structured_permissions.add((provider, canonical))

        for member, role in _gcp_bindings(data):
            provider = "gcp"
            src = graph.add_node(provider, "member", member, source=source.name)
            dst = graph.add_node(provider, "role", role, source=source.name)
            edge_id = graph.add_edge(provider, src, dst, "assigned_role", evidence={"source": source.name, "json_path": "binding", "permission": role.lower()})
            canonical = role.lower().strip()
            if canonical in SENSITIVE[provider]:
                relation, reason = SENSITIVE[provider][canonical]
                add_indicator(provider=provider, principal=member, permission=canonical, relation=relation, reason=reason, source=source, json_path="binding", edge_id=edge_id)
                structured_permissions.add((provider, canonical))

        hints = _provider_hints(source, data)
        permission_map = {provider: _permissions(data, provider) for provider in SENSITIVE}
        active_providers = {provider for provider, hits in permission_map.items() if hits} | hints
        if not active_providers:
            active_providers = {"generic"}

        for provider in sorted(active_providers):
            principal = _principal_name(data, source, provider)
            principal_kind = "service_account" if "serviceaccount" in principal.lower() or principal.lower().startswith("serviceaccount:") else "service_principal" if provider == "azure" else "principal"
            principal_id = graph.add_node(provider, principal_kind, principal, source=source.name)
            for permission, json_path in permission_map.get(provider, []):
                if (provider, permission) in structured_permissions:
                    continue
                relation, reason = SENSITIVE[provider][permission]
                perm_id = graph.add_node(provider, "permission_or_role", permission, source=source.name)
                edge_id = graph.add_edge(provider, principal_id, perm_id, relation, evidence={"source": source.name, "json_path": json_path, "permission": permission})
                add_indicator(provider=provider, principal=principal, permission=permission, relation=relation, reason=reason, source=source, json_path=json_path, edge_id=edge_id)

    return {
        "schema_version": "1",
        "analysis": "read_only_cloud_iam_graph",
        "files": [str(item) for item in files[:max_files]],
        "nodes": sorted(graph.nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(graph.edges, key=lambda item: item["id"]),
        "paths": sorted(indicators, key=lambda item: (item["source"], item["provider"], item["principal"], item["permission_or_role"], item.get("json_path", ""))),
        "malformed": malformed,
        "summary": {"files": len(files[:max_files]), "nodes": len(graph.nodes), "edges": len(graph.edges), "path_indicators": len(indicators), "malformed": len(malformed)},
        "boundary": "Permission and role indicators are evidence-backed leads. No role assumption, credential use, policy modification, resource creation, or exploitability claim is performed.",
    }
