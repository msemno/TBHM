"""
Phase: lateral_movement_paths   (v3.9-safe)

Read-only Active Directory graph analysis. It does NOT collect credentials,
request tickets, crack/relay hashes, execute commands, or move laterally. It
consumes either:

  * a normalized nodes/edges graph supplied with --ad-graph;
  * bounded BloodHound/SharpHound JSON or ZIP supplied with
    --ad-access-results; or
  * the read-only inventory produced by add_net_ad.

It builds a directed graph of principals -> rights -> targets and computes
shortest exposure paths to high-value/Tier-0 objects using deterministic BFS.
The path output is an unconfirmed defensive lead, never an execution plan.
"""
from __future__ import annotations

import json
import zipfile
from collections import defaultdict, deque
from pathlib import Path

# Edge types that can represent a meaningful privilege/control relationship.
_ATTACK_EDGES = {
    "MemberOf", "AdminTo", "HasSession", "GenericAll", "GenericWrite",
    "WriteDacl", "WriteOwner", "Owns", "ForceChangePassword",
    "AllowedToDelegate", "AllowedToAct", "AddMember", "DCSync",
    "GetChanges", "GetChangesAll", "AllExtendedRights", "CanRDP",
    "CanPSRemote",
}
_HVT_MARKERS = (
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
    "DOMAIN CONTROLLERS", "TIER-0", "KRBTGT",
)
_BH_TYPES = {"users", "groups", "computers", "domains", "gpos", "ous", "containers"}
_MAX_DOC_BYTES = 50_000_000
_MAX_TOTAL_BYTES = 250_000_000
_MAX_OBJECTS = 200_000
_MAX_EDGES = 500_000


def _safe_json_bytes(raw: bytes):
    if len(raw) > _MAX_DOC_BYTES:
        return None
    try:
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return None


def _iter_bloodhound_docs(path: Path):
    """Yield bounded BloodHound JSON documents without archive extraction."""
    total = 0
    candidates = [path] if path.is_file() else list(path.rglob("*"))[:5000] if path.is_dir() else []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        suffix = candidate.suffix.lower()
        try:
            size = candidate.stat().st_size
        except OSError:
            continue
        if size > _MAX_TOTAL_BYTES:
            continue
        if suffix == ".json":
            try:
                raw = candidate.read_bytes()
            except OSError:
                continue
            total += len(raw)
            if total > _MAX_TOTAL_BYTES:
                return
            data = _safe_json_bytes(raw)
            if isinstance(data, dict):
                yield data, str(candidate)
        elif suffix == ".zip":
            try:
                with zipfile.ZipFile(candidate) as archive:
                    for info in archive.infolist()[:1000]:
                        if info.is_dir() or info.flag_bits & 0x1:
                            continue
                        if Path(info.filename).suffix.lower() != ".json":
                            continue
                        if info.file_size > _MAX_DOC_BYTES:
                            continue
                        total += info.file_size
                        if total > _MAX_TOTAL_BYTES:
                            return
                        data = _safe_json_bytes(archive.read(info))
                        if isinstance(data, dict):
                            yield data, f"{candidate}:{info.filename}"
            except (OSError, zipfile.BadZipFile):
                continue


def _bloodhound_graph(path: Path):
    id_to_name: dict[str, str] = {}
    highvalue_ids: set[str] = set()
    raw_edges: list[tuple[str, str, str]] = []
    object_count = 0

    for data, _source in _iter_bloodhound_docs(path):
        meta = data.get("meta") or {}
        if str(meta.get("type", "")).lower() not in _BH_TYPES or not isinstance(data.get("data"), list):
            continue
        for obj in data.get("data", []):
            if not isinstance(obj, dict) or object_count >= _MAX_OBJECTS:
                break
            object_count += 1
            oid = str(obj.get("ObjectIdentifier") or obj.get("objectid") or "")
            props = obj.get("Properties") or obj.get("properties") or {}
            if not isinstance(props, dict):
                props = {}
            name = str(props.get("name") or props.get("samaccountname") or oid)
            if oid:
                id_to_name[oid] = name
                if props.get("highvalue") is True:
                    highvalue_ids.add(oid)

            for ace in obj.get("Aces", []) or []:
                if len(raw_edges) >= _MAX_EDGES or not isinstance(ace, dict):
                    break
                principal = str(ace.get("PrincipalSID") or ace.get("principalid") or "")
                right = str(ace.get("RightName") or ace.get("rightname") or "")
                if principal and oid and right in _ATTACK_EDGES:
                    raw_edges.append((principal, right, oid))

            for member in obj.get("Members", []) or []:
                if len(raw_edges) >= _MAX_EDGES or not isinstance(member, dict):
                    break
                member_id = str(member.get("ObjectIdentifier") or member.get("objectid") or "")
                if member_id and oid:
                    raw_edges.append((member_id, "MemberOf", oid))

            for target in obj.get("AllowedToDelegate", []) or []:
                if len(raw_edges) >= _MAX_EDGES:
                    break
                target_id = str(target.get("ObjectIdentifier") if isinstance(target, dict) else target)
                if oid and target_id:
                    raw_edges.append((oid, "AllowedToDelegate", target_id))

            for principal in obj.get("AllowedToAct", []) or []:
                if len(raw_edges) >= _MAX_EDGES:
                    break
                principal_id = str(principal.get("ObjectIdentifier") if isinstance(principal, dict) else principal)
                if principal_id and oid:
                    raw_edges.append((principal_id, "AllowedToAct", oid))

            collection_edges = {
                "LocalAdmins": "AdminTo",
                "RemoteDesktopUsers": "CanRDP",
                "PSRemoteUsers": "CanPSRemote",
            }
            for key, edge_type in collection_edges.items():
                collection = obj.get(key) or {}
                results = collection.get("Results", []) if isinstance(collection, dict) else collection
                for principal in results or []:
                    if len(raw_edges) >= _MAX_EDGES:
                        break
                    principal_id = str(principal.get("ObjectIdentifier") if isinstance(principal, dict) else principal)
                    if principal_id and oid:
                        raw_edges.append((principal_id, edge_type, oid))

            sessions = obj.get("Sessions") or {}
            session_results = sessions.get("Results", []) if isinstance(sessions, dict) else sessions
            for session in session_results or []:
                if len(raw_edges) >= _MAX_EDGES or not isinstance(session, dict):
                    break
                user_id = str(session.get("UserSID") or session.get("ObjectIdentifier") or "")
                computer_id = str(session.get("ComputerSID") or oid)
                if user_id and computer_id:
                    raw_edges.append((user_id, "HasSession", computer_id))

    def label(identifier: str) -> str:
        return id_to_name.get(identifier, identifier)

    edges = [(label(src), edge_type, label(dst)) for src, edge_type, dst in raw_edges]
    nodes = set(id_to_name.values()) | {s for s, _, _ in edges} | {d for _, _, d in edges}
    highvalue = {label(identifier) for identifier in highvalue_ids}
    return nodes, edges, highvalue


def _normalized_graph(path: Path):
    try:
        data = json.loads(path.read_text())
    except Exception:
        return set(), [], set()
    if not isinstance(data, dict) or not isinstance(data.get("edges"), list):
        return set(), [], set()

    names: dict[str, str] = {}
    highvalue: set[str] = set()
    nodes: set[str] = set()
    for node in data.get("nodes", []) or []:
        if isinstance(node, dict):
            identifier = str(node.get("id") or node.get("name") or "")
            name = str(node.get("name") or identifier)
            if identifier:
                names[identifier] = name
                nodes.add(name)
                if node.get("highvalue") is True:
                    highvalue.add(name)
        elif node not in (None, ""):
            nodes.add(str(node))

    edges = []
    for edge in data.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("source") or "")
        dst = str(edge.get("target") or "")
        edge_type = str(edge.get("type") or "MemberOf")
        if src and dst:
            src, dst = names.get(src, src), names.get(dst, dst)
            edges.append((src, edge_type, dst))
            nodes.update((src, dst))
    return nodes, edges, highvalue


def _load_graph(ctx):
    """Return (nodes, edges, explicit_highvalue) from approved local evidence."""
    path = getattr(ctx.args, "ad_graph", None)
    if path and Path(path).is_file():
        nodes, edges, highvalue = _normalized_graph(Path(path))
        if edges:
            return nodes, edges, highvalue
        nodes, edges, highvalue = _bloodhound_graph(Path(path))
        if edges:
            return nodes, edges, highvalue

    ad_results = getattr(ctx.args, "ad_access_results", None)
    if ad_results:
        nodes, edges, highvalue = _bloodhound_graph(Path(ad_results))
        if edges:
            return nodes, edges, highvalue

    # Fall back to add_net_ad read-only output.
    addon_root = ctx.output / "evidence" / "v3_addons"
    for candidate in (addon_root.rglob("*.json") if addon_root.is_dir() else []):
        try:
            data = json.loads(candidate.read_text())
        except Exception:
            continue
        if isinstance(data, dict) and (
            "spn_accounts" in data or "delegation" in data or "asrep" in data
        ):
            nodes, edges = set(), []
            for account in data.get("spn_accounts", []) or []:
                name = account.get("sam") or account.get("name") or str(account)
                nodes.add(name)
                edges.append((name, "AllowedToDelegate", "DOMAIN ADMINS"))
            for account in data.get("delegation", []) or []:
                name = account.get("sam") or account.get("name") or str(account)
                nodes.add(name)
                edges.append((name, "AllowedToDelegate", "DOMAIN CONTROLLERS"))
            if edges:
                return nodes, edges, {"DOMAIN ADMINS", "DOMAIN CONTROLLERS"}
    return set(), [], set()


def _shortest_paths(nodes, edges, sources, is_hvt):
    adjacency = defaultdict(list)
    for source, edge_type, destination in edges:
        if edge_type in _ATTACK_EDGES:
            adjacency[source].append((destination, edge_type))
    paths = []
    for source in sources:
        queue = deque([(source, [source], [])])
        seen = {source}
        while queue:
            node, node_path, edge_path = queue.popleft()
            if is_hvt(node) and len(node_path) > 1:
                paths.append({
                    "from": source,
                    "to": node,
                    "hops": len(node_path) - 1,
                    "path": node_path,
                    "edges": edge_path,
                })
                break
            for next_node, edge_type in adjacency.get(node, []):
                if next_node not in seen:
                    seen.add(next_node)
                    queue.append((next_node, node_path + [next_node], edge_path + [edge_type]))
    return paths


def run(ctx):
    nodes, edges, explicit_highvalue = _load_graph(ctx)
    if not edges:
        return

    out_dir = ctx.output / "lateral_movement"
    out_dir.mkdir(exist_ok=True)

    def is_hvt(node):
        return node in explicit_highvalue or any(marker in str(node).upper() for marker in _HVT_MARKERS)

    sources = [node for node in nodes if not is_hvt(node)]
    paths = _shortest_paths(nodes, edges, sources, is_hvt)
    paths.sort(key=lambda item: item["hops"])

    export = {
        "nodes": [{"id": node, "highvalue": is_hvt(node)} for node in sorted(nodes)],
        "edges": [{"source": src, "type": edge_type, "target": dst} for src, edge_type, dst in edges],
    }
    (out_dir / "ad_graph_export.json").write_text(json.dumps(export, indent=2))
    (out_dir / "attack_paths.json").write_text(json.dumps(paths, indent=2))

    markdown = [
        "# AD privilege-path exposure (read-only graph analysis)", "",
        "Computed from supplied/collected AD graph evidence. No live AD action was taken.",
        "Every path is an unconfirmed defensive lead and must be validated against current ACLs and asset ownership.", "",
    ]
    for path in paths[:40]:
        chain = " → ".join(path["path"])
        markdown.append(
            f"- **{path['hops']} hop(s)** to `{path['to']}`: {chain} "
            f"(edges: {', '.join(path['edges'])})"
        )
    (out_dir / "attack_paths.md").write_text("\n".join(markdown))

    for path in paths[:20]:
        ctx.save_finding({
            "phase": "lateral_movement_paths",
            "severity": "HIGH" if path["hops"] <= 2 else "MEDIUM",
            "confidence": "MEDIUM",
            "title": f"AD privilege-path exposure to {path['to']} in {path['hops']} hop(s)",
            "target": path["from"],
            "url": "",
            "description": (
                "Read-only graph analysis identified a potential control path: "
                + " → ".join(path["path"])
                + f" (relationships: {', '.join(path['edges'])}). No credential or lateral-movement action was executed."
            ),
            "evidence": json.dumps(path)[:1200],
            "impact": "If the graph is current and the relationships are effective, a short path may expose Tier-0 privileges.",
            "remediation": (
                "Validate the effective ACL/delegation/membership relationships, remove unnecessary control, "
                "apply tiered administration, and regenerate the graph to confirm the path is broken."
            ),
            "cwe": "CWE-269",
            "mrs_score": 85 if path["hops"] <= 2 else 65,
            "status": "lead",
            "finding_class": "lead",
            "validation_required": "Confirm graph freshness and each effective relationship without executing the path.",
        })

    ctx.log(
        "OK", "lateral_movement_paths",
        f"graph: {len(nodes)} nodes / {len(edges)} edges | {len(paths)} path lead(s) to HVT",
    )
