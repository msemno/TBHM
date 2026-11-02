"""
Phase: attack_path   (v3.2)   [--chain-simulate]

Read-only post-processing. TBHM finds isolated issues; this phase correlates the
whole findings set into plausible attack *chains* and maps every finding onto
MITRE ATT&CK. It produces:

    source_code intel + web + AD findings  ->  capability tags  ->  chains
                                            ->  chained_attack_path.md
                                            ->  attack_path.json
                                            ->  mitre_attack_layer.json (Navigator)

It never executes anything. Chains are hypotheses built from findings that
already exist in this run's database, expressed the way a report reviewer or an
engagement lead would narrate an adversary's movement.
"""
from __future__ import annotations

import json
from collections import defaultdict

from core import attack_knowledge as AK
from core.evidence_graph import canonical_asset


def run(ctx):
    findings = []
    try:
        findings = [f for f in ctx.storage.all_findings() if f.get('phase') != 'attack_path']
    except Exception as e:
        ctx.log("WARN", "attack_path", f"could not load findings: {e}")
        return
    if not findings:
        ctx.log("INFO", "attack_path", "no findings to correlate — skipping")
        return

    out_dir = ctx.output / "attack_path"
    out_dir.mkdir(exist_ok=True)

    # 1. MITRE ATT&CK mapping (always)
    ttp_index = defaultdict(list)
    mapped = 0
    for f in findings:
        m = AK.map_attack(f)
        if m:
            tactic, tid, tname = m
            ttp_index[(tactic, tid, tname)].append(f)
            mapped += 1
    mitre = [{
        "tactic": tactic, "technique_id": tid, "technique": tname,
        "finding_count": len(fs),
        "example": fs[0].get("title", "")[:120],
        "severities": sorted({x.get("severity", "INFO") for x in fs}),
    } for (tactic, tid, tname), fs in sorted(ttp_index.items())]
    (out_dir / "mitre_attack_map.json").write_text(json.dumps(mitre, indent=2))

    # ATT&CK Navigator layer (importable at mitre-attack.github.io/attack-navigator)
    layer = {
        "name": f"TBHM {ctx.profile.get('name','run')}",
        "versions": {"layer": "4.5", "navigator": "4.9.0", "attack": "14"},
        "domain": "enterprise-attack",
        "description": "Conceptual technique associations from keyword rules; adversary behavior is not established.",
        "techniques": [{
            "techniqueID": tid.split(".")[0],
            "score": len(fs),
            "comment": f"{len(fs)} finding(s); e.g. {fs[0].get('title','')[:80]}",
            "enabled": True,
        } for (tactic, tid, tname), fs in ttp_index.items()],
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0,
                     "maxValue": max((len(v) for v in ttp_index.values()), default=1)},
    }
    (out_dir / "mitre_attack_layer.json").write_text(json.dumps(layer, indent=2))

    # 2. Exact asset grouping. Tags are hypotheses, not acquired capabilities.
    cap_evidence = defaultdict(list)
    by_asset = defaultdict(lambda: defaultdict(list))
    for f in findings:
        for cap in AK.capabilities_of(f):
            cap_evidence[cap].append(f)
            by_asset[canonical_asset(f)][cap].append(f)
    present_caps = set(cap_evidence.keys())

    # 3. chain matching
    chains = []
    for asset, candidates in sorted(by_asset.items()):
      if not getattr(ctx.args, 'chain_simulate', False) or asset == 'unknown':
        continue
      for name, required, template in AK.CHAIN_RULES:
        if all(c in candidates for c in required):
            # Distinct records must support distinct steps. One broad title
            # cannot manufacture a multi-step path by matching several tags.
            selected = []
            def choose(index, used):
                if index == len(required):
                    return True
                for candidate in candidates[required[index]][:50]:
                    identity = candidate.get('id', id(candidate))
                    if identity not in used:
                        selected.append(candidate)
                        if choose(index+1, used | {identity}):
                            return True
                        selected.pop()
                return False
            if not choose(0, set()):
                continue
            narrative = ('Review hypothesis on '+asset+': '+name+'. Co-occurring '
                         'findings do not demonstrate a usable sequence. Validate '
                         'identity, service compatibility, required access and '
                         'each transition with separate captured evidence.')
            steps = []
            for c, e in zip(required, selected):
                    steps.append({
                        "capability": c,
                        "finding_id": e.get('id'), "status": "unverified_precondition",
                        "finding": e.get("title", ""),
                        "severity": e.get("severity", "INFO"),
                        "phase": e.get("phase", ""),
                        "target": e.get("target", "") or e.get("url", ""),
                    })
            # highest severity in the chain drives the chain rating
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            worst = min((sev_rank.get(s["severity"], 4) for s in steps), default=4)
            chain_sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][worst]
            chains.append({
                "name": name, "severity": chain_sev,
                "asset": asset, "status": "hypothesis", "verified_path": False,
                "missing_evidence": ['step preconditions', 'identity compatibility', 'captured transition proof'],
                "capabilities": required, "narrative": narrative, "steps": steps,
            })

    (out_dir / "attack_path.json").write_text(json.dumps({
        "schema": "tbhm.attack-path/2", "chain_simulation_enabled": bool(getattr(ctx.args, 'chain_simulate', False)),
        "capabilities_present": sorted(present_caps),
        "chains": chains,
    }, indent=2))

    # 4. narrative markdown
    md = ["# Chained attack paths (hypotheses)", "",
          "_Generated from this run's findings. Read-only correlation — no actions "
          "were executed. Each chain is a hypothesis for the engagement narrative._", ""]
    if not chains:
        md += ["No multi-stage chains matched. Individual findings still stand on "
               "their own — see the main report."]
    for i, ch in enumerate(chains, 1):
        md += [f"## {i}. {ch['name']}  \u2014  {ch['severity']}", "",
               ch["narrative"], "", "**Chain steps:**", ""]
        for s in ch["steps"]:
            md += [f"- `[{s['severity']}]` **{s['capability']}** \u2014 {s['finding']} "
                   f"({s['phase']} \u2192 {s['target']})"]
        md += [""]
    (out_dir / "chained_attack_path.md").write_text("\n".join(md))

    # Hypotheses stay in the graph/report artifacts. They are not synthetic
    # vulnerabilities and must not amplify severity or feed subsequent runs.

    ctx.log("OK", "attack_path",
            f"MITRE: {mapped}/{len(findings)} findings mapped to {len(mitre)} techniques | "
            f"{len(chains)} attack chain(s) → chained_attack_path.md")
