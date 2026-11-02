"""
Phase: dashboard
Builds a SINGLE static HTML file: dashboard.html

Why static and not a server?
  - No Node/Python daemon hogging RAM
  - Open in browser, no install needed
  - Searchable, filterable, sortable in browser via vanilla JS
  - You can email/share it as one file

Reads from:
  - findings table (storage.py)
  - correlations.json (correlation.py)
  - recon/alive.txt + recon/ports.json (recon summary)
"""
from __future__ import annotations
import html
import json
from pathlib import Path

from core import correlation


def run(ctx):
    findings = ctx.storage.all_findings()
    if not findings:
        ctx.log("INFO", "dashboard", "no findings — generating empty dashboard")

    # Build correlation data
    correlations = correlation.write(ctx.output, findings)

    # Stats
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_counts[f.get("severity", "INFO")] = sev_counts.get(f.get("severity", "INFO"), 0) + 1

    n_alive = 0
    alive_file = ctx.output / "recon" / "alive.txt"
    if alive_file.exists():
        n_alive = len([l for l in alive_file.read_text().splitlines() if l.strip()])

    # Embed findings as JSON for client-side filtering
    findings_json = json.dumps([_safe_finding(f) for f in findings], default=str)
    correlations_json = json.dumps(correlations, default=str)

    html_doc = _TEMPLATE.format(
        target=", ".join(ctx.targets[:3]),
        n_findings=len(findings),
        n_alive=n_alive,
        sev_critical=sev_counts.get("CRITICAL", 0),
        sev_high=sev_counts.get("HIGH", 0),
        sev_medium=sev_counts.get("MEDIUM", 0),
        sev_low=sev_counts.get("LOW", 0),
        sev_info=sev_counts.get("INFO", 0),
        findings_json=findings_json,
        correlations_json=correlations_json,
        n_clusters=len(correlations.get("clusters", [])),
        n_links=len(correlations.get("links", [])),
    )
    out = ctx.output / "dashboard.html"
    out.write_text(html_doc, encoding="utf-8")
    ctx.log("OK", "dashboard", f"dashboard → {out}")
    ctx.log("INFO", "dashboard", f"  open: file://{out.absolute()}")


def _safe_finding(f):
    """Strip very large fields, keep what dashboard needs."""
    out = {}
    for k in ("id", "phase", "severity", "confidence", "title", "target",
              "url", "method", "parameter", "payload", "evidence",
              "description", "impact", "remediation", "cwe", "mrs_score"):
        v = f.get(k)
        if isinstance(v, str) and len(v) > 1500:
            v = v[:1500] + "…"
        out[k] = v
    return out


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TBHM Dashboard — {target}</title>
<style>
  :root {{
    --bg: #0f1419; --bg2: #1a1f2e; --bd: #2a3142;
    --tx: #e5e9f0; --tx2: #8b95a8;
    --crit: #ef4444; --high: #f97316; --med: #eab308;
    --low: #3b82f6; --info: #6b7280;
    --green: #10b981;
  }}
  body {{ background: var(--bg); color: var(--tx); font-family: -apple-system,
         BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; }}
  header {{ background: var(--bg2); border-bottom: 1px solid var(--bd);
           padding: 16px 24px; display: flex; align-items: center; gap: 16px; }}
  header h1 {{ margin: 0; font-size: 18px; font-weight: 600; }}
  header .target {{ color: var(--tx2); font-size: 13px; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
           gap: 12px; margin-bottom: 24px; }}
  .stat {{ background: var(--bg2); border: 1px solid var(--bd); border-radius: 6px;
          padding: 14px; }}
  .stat .label {{ font-size: 11px; text-transform: uppercase; color: var(--tx2);
                 letter-spacing: 0.05em; }}
  .stat .value {{ font-size: 26px; font-weight: 700; margin-top: 4px; }}
  .stat.crit .value {{ color: var(--crit); }}
  .stat.high .value {{ color: var(--high); }}
  .stat.med  .value {{ color: var(--med); }}
  .stat.low  .value {{ color: var(--low); }}
  .stat.info .value {{ color: var(--info); }}
  .toolbar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
  .toolbar input, .toolbar select {{
    background: var(--bg2); border: 1px solid var(--bd); color: var(--tx);
    padding: 8px 12px; border-radius: 4px; font-size: 13px;
  }}
  .toolbar input {{ flex: 1; min-width: 200px; }}
  table {{ width: 100%; background: var(--bg2); border: 1px solid var(--bd);
          border-radius: 6px; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--bd); }}
  th {{ font-weight: 600; font-size: 11px; text-transform: uppercase;
       color: var(--tx2); letter-spacing: 0.05em; cursor: pointer; user-select: none; }}
  th:hover {{ color: var(--tx); }}
  tr {{ cursor: pointer; }}
  tr:hover td {{ background: rgba(255,255,255,0.03); }}
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 3px;
         font-size: 11px; font-weight: 600; }}
  .sev-CRITICAL {{ background: var(--crit); color: white; }}
  .sev-HIGH     {{ background: var(--high); color: white; }}
  .sev-MEDIUM   {{ background: var(--med);  color: black; }}
  .sev-LOW      {{ background: var(--low);  color: white; }}
  .sev-INFO     {{ background: var(--info); color: white; }}
  .url {{ color: var(--tx2); font-family: "SF Mono", Menlo, monospace; font-size: 12px;
         max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .phase-tag {{ background: var(--bd); padding: 2px 6px; border-radius: 3px;
               font-size: 10px; text-transform: uppercase; color: var(--tx2); }}
  /* Modal */
  .overlay {{ position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: none;
             align-items: center; justify-content: center; z-index: 100; }}
  .overlay.open {{ display: flex; }}
  .modal {{ background: var(--bg2); border: 1px solid var(--bd); border-radius: 8px;
           padding: 24px; max-width: 900px; width: 92%; max-height: 85vh; overflow: auto; }}
  .modal h2 {{ margin: 0 0 8px 0; font-size: 18px; }}
  .modal .meta {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }}
  .modal .meta span {{ background: var(--bd); padding: 4px 10px; border-radius: 3px;
                      font-size: 12px; }}
  .modal h3 {{ font-size: 12px; text-transform: uppercase; color: var(--tx2);
              margin: 16px 0 6px 0; }}
  .modal pre {{ background: var(--bg); padding: 12px; border-radius: 4px;
               border: 1px solid var(--bd); overflow-x: auto; font-size: 12px;
               white-space: pre-wrap; word-break: break-word; }}
  .close {{ float: right; background: none; border: none; color: var(--tx2);
           font-size: 24px; cursor: pointer; padding: 0; }}
  .close:hover {{ color: var(--tx); }}
  .badge {{ background: var(--green); color: black; padding: 2px 8px;
           border-radius: 10px; font-size: 11px; font-weight: 600; }}
</style>
</head>
<body>
<header>
  <h1>🎯 TBHM Dashboard</h1>
  <span class="target">{target}</span>
  <span style="margin-left:auto;font-size:12px;color:var(--tx2)">
    {n_clusters} clusters · {n_links} correlations
  </span>
</header>

<div class="container">
  <div class="stats">
    <div class="stat"><div class="label">Live hosts</div><div class="value">{n_alive}</div></div>
    <div class="stat"><div class="label">All findings</div><div class="value">{n_findings}</div></div>
    <div class="stat crit"><div class="label">Critical</div><div class="value">{sev_critical}</div></div>
    <div class="stat high"><div class="label">High</div><div class="value">{sev_high}</div></div>
    <div class="stat med"><div class="label">Medium</div><div class="value">{sev_medium}</div></div>
    <div class="stat low"><div class="label">Low</div><div class="value">{sev_low}</div></div>
    <div class="stat info"><div class="label">Info</div><div class="value">{sev_info}</div></div>
  </div>

  <div class="toolbar">
    <input id="search" placeholder="Search title, URL, parameter, payload…" autofocus>
    <select id="filter-sev">
      <option value="">All severities</option>
      <option value="CRITICAL">Critical only</option>
      <option value="HIGH">High+</option>
      <option value="MEDIUM">Medium+</option>
      <option value="LOW">Low+</option>
    </select>
    <select id="filter-phase">
      <option value="">All phases</option>
    </select>
  </div>

  <table id="findings-table">
    <thead>
      <tr>
        <th data-sort="severity">Severity</th>
        <th data-sort="phase">Phase</th>
        <th data-sort="title">Title</th>
        <th data-sort="target">Target</th>
        <th data-sort="url">URL</th>
        <th data-sort="parameter">Parameter</th>
      </tr>
    </thead>
    <tbody id="findings-body"></tbody>
  </table>
</div>

<div class="overlay" id="overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <button class="close" onclick="closeModal()">×</button>
    <div id="modal-content"></div>
  </div>
</div>

<script>
const FINDINGS  = {findings_json};
const CORREL    = {correlations_json};
const SEV_ORDER = {{CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4}};

function escapeHTML(s) {{
  return (s ?? "").toString()
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}}

function getFiltered() {{
  const q = document.getElementById("search").value.toLowerCase();
  const sf = document.getElementById("filter-sev").value;
  const pf = document.getElementById("filter-phase").value;
  return FINDINGS.filter(f => {{
    if (q) {{
      const hay = [f.title, f.url, f.parameter, f.payload, f.target, f.evidence]
        .filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }}
    if (sf) {{
      const order = SEV_ORDER[sf];
      if (SEV_ORDER[f.severity] > order) return false;
    }}
    if (pf && f.phase !== pf) return false;
    return true;
  }});
}}

function render() {{
  const rows = getFiltered();
  rows.sort((a,b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const tbody = document.getElementById("findings-body");
  tbody.innerHTML = rows.map((f,i) =>
    `<tr onclick="showDetail(${{FINDINGS.indexOf(f)}})">
      <td><span class="sev sev-${{f.severity}}">${{f.severity}}</span></td>
      <td><span class="phase-tag">${{escapeHTML(f.phase)}}</span></td>
      <td><strong>${{escapeHTML(f.title)}}</strong></td>
      <td>${{escapeHTML(f.target || "")}}</td>
      <td class="url" title="${{escapeHTML(f.url || "")}}">${{escapeHTML(f.url || "")}}</td>
      <td>${{escapeHTML(f.parameter || "")}}</td>
    </tr>`
  ).join("");
  if (rows.length === 0) {{
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--tx2)">No matching findings</td></tr>';
  }}
}}

function showDetail(idx) {{
  const f = FINDINGS[idx];
  if (!f) return;
  const html = `
    <span class="sev sev-${{f.severity}}">${{f.severity}}</span>
    <span class="badge">${{f.confidence}} confidence</span>
    <h2>${{escapeHTML(f.title)}}</h2>
    <div class="meta">
      <span><strong>Phase:</strong> ${{escapeHTML(f.phase)}}</span>
      ${{f.cwe ? `<span><strong>CWE:</strong> ${{escapeHTML(f.cwe)}}</span>` : ""}}
      ${{f.mrs_score ? `<span><strong>MRS:</strong> ${{f.mrs_score}}</span>` : ""}}
      ${{f.method ? `<span><strong>Method:</strong> ${{escapeHTML(f.method)}}</span>` : ""}}
    </div>
    ${{f.url ? `<h3>URL</h3><pre>${{escapeHTML(f.url)}}</pre>` : ""}}
    ${{f.parameter ? `<h3>Parameter</h3><pre>${{escapeHTML(f.parameter)}}</pre>` : ""}}
    ${{f.payload ? `<h3>Payload</h3><pre>${{escapeHTML(f.payload)}}</pre>` : ""}}
    ${{f.evidence ? `<h3>Evidence</h3><pre>${{escapeHTML(f.evidence)}}</pre>` : ""}}
    ${{f.description ? `<h3>Description</h3><pre>${{escapeHTML(f.description)}}</pre>` : ""}}
    ${{f.impact ? `<h3>Impact</h3><pre>${{escapeHTML(f.impact)}}</pre>` : ""}}
    ${{f.remediation ? `<h3>Remediation</h3><pre>${{escapeHTML(f.remediation)}}</pre>` : ""}}
  `;
  document.getElementById("modal-content").innerHTML = html;
  document.getElementById("overlay").classList.add("open");
}}

function closeModal() {{
  document.getElementById("overlay").classList.remove("open");
}}

// Init filter dropdowns
(function() {{
  const phases = [...new Set(FINDINGS.map(f => f.phase).filter(Boolean))].sort();
  const sel = document.getElementById("filter-phase");
  for (const p of phases) {{
    const opt = document.createElement("option");
    opt.value = p; opt.textContent = p;
    sel.appendChild(opt);
  }}
  document.getElementById("search").addEventListener("input", render);
  document.getElementById("filter-sev").addEventListener("change", render);
  document.getElementById("filter-phase").addEventListener("change", render);
  document.addEventListener("keydown", e => {{
    if (e.key === "Escape") closeModal();
  }});
  render();
}})();
</script>
</body>
</html>
"""
