"""
Phase: k8s_recon_safe   (v3.3)

Read-only Kubernetes attack-surface review. Given --k8s-api URL(s) (or discovered
6443/10250/2379 services) it performs anonymous, unauthenticated GET probes that
reveal common misconfigurations WITHOUT changing anything:

  * anonymous kube-apiserver access (/version, /api, /apis, unauthenticated list)
  * open kubelet read-only API (:10250/pods, :10255/pods)
  * exposed etcd (:2379/version)
  * open metrics/healthz that leak cluster info

No pods are created, no exec, no config changes. Anonymous reads only.
Honors --no-destructive (only GETs are issued regardless).
"""
from __future__ import annotations

import json
from urllib.parse import urlparse


def _targets(ctx):
    out = []
    raw = getattr(ctx.args, "k8s_api", None)
    if raw:
        out += [x.strip() for x in raw.split(",") if x.strip()]
    for t in (ctx.targets or []):
        host = t if t.startswith("http") else t
        host = urlparse(host).netloc or host
        host = host.split(":")[0]
        out += [f"https://{host}:6443", f"https://{host}:10250",
                f"http://{host}:10255", f"http://{host}:2379"]
    seen, res = set(), []
    for u in out:
        if u not in seen:
            seen.add(u); res.append(u)
    return res[:40]


_PROBES = [
    ("apiserver /version", "/version", "gitVersion"),
    ("apiserver anonymous /api", "/api", "versions"),
    ("apiserver anonymous /apis", "/apis", "groups"),
    ("apiserver list namespaces (anon)", "/api/v1/namespaces", "NamespaceList"),
    ("apiserver list pods (anon)", "/api/v1/pods", "PodList"),
    ("kubelet /pods", "/pods", "PodList"),
    ("kubelet /runningpods", "/runningpods/", "PodList"),
    ("etcd /version", "/version", "etcdserver"),
    ("healthz", "/healthz", "ok"),
]


def run(ctx):
    if not getattr(ctx.args, "k8s_api", None) and not ctx.profile.get("active_probes", False):
        return
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except Exception:
        ctx.log("WARN", "k8s_recon_safe", "requests unavailable — skipping")
        return

    out_dir = ctx.output / "k8s"
    out_dir.mkdir(exist_ok=True)
    results, findings = [], 0

    for base in _targets(ctx):
        for label, path, marker in _PROBES:
            ctx.runner.throttle("k8s")
            url = base.rstrip("/") + path
            try:
                r = requests.get(url, timeout=8, verify=False)
            except Exception:
                continue
            hit = r.status_code == 200 and marker.lower() in r.text.lower()
            anon_list = (r.status_code == 200 and "List" in marker
                         and '"items"' in r.text)
            if hit or anon_list:
                results.append({"url": url, "check": label, "status": r.status_code})
                sev = "HIGH" if ("anon" in label or "kubelet" in label
                                 or "etcd" in label) else "LOW"
                ctx.save_finding({
                    "phase": "k8s_recon_safe", "severity": sev,
                    "confidence": "MEDIUM",
                    "title": f"Kubernetes exposure: {label}",
                    "target": base, "url": url,
                    "description": f"Anonymous read succeeded for '{label}'. Read-only probe; "
                                   f"no cluster state was changed.",
                    "evidence": f"GET {url} -> {r.status_code} (matched '{marker}')",
                    "impact": "Anonymous cluster info/list access aids reconnaissance and can expose "
                              "secrets, service accounts, or workload details.",
                    "remediation": "Disable anonymous-auth on the apiserver/kubelet, restrict 10250/10255/"
                                   "2379 by network policy, and enforce RBAC + node authorizer.",
                    "cwe": "CWE-306", "cvss": "7.5" if sev == "HIGH" else "4.0",
                    "mrs_score": 80 if sev == "HIGH" else 30,
                })
                findings += 1

    (out_dir / "k8s_recon.json").write_text(json.dumps(results, indent=2))
    ctx.log("OK", "k8s_recon_safe",
            f"{len(results)} anonymous exposure(s) across probed endpoints | {findings} finding(s) "
            f"→ k8s_recon.json")
