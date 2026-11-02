"""
Phase: visual
Screenshots of all alive hosts. Useful triage tool — at a glance you can
see which hosts are admin panels, error pages, login screens, etc.

Tools:
  - gowitness (preferred)
  - aquatone (fallback)
"""
from __future__ import annotations
from core import intensity


def run(ctx):
    if not ctx.profile.get("active_probes", True):
        return
    if not intensity.get(ctx.profile, "screenshot_enabled", False):
        return

    alive_file = ctx.output / "recon" / "alive.txt"
    if not alive_file.exists():
        return
    alive = ctx.runner.read_lines(alive_file)
    if not alive:
        return

    out_dir = ctx.output / "screenshots"
    out_dir.mkdir(exist_ok=True)
    max_hosts = intensity.get(ctx.profile, "max_alive_hosts_to_scan", 50)

    if ctx.runner.has("gowitness"):
        ctx.log("INFO", "visual", f"gowitness on {min(len(alive),max_hosts)} hosts…")
        # gowitness reads from a file and writes PNGs to screenshots/
        rc, out, _ = ctx.runner.run(
            ["gowitness", "file", "-f", str(alive_file),
             "-P", str(out_dir), "--no-http"],
            timeout=1800, log_name="gowitness"
        )
        screenshots = list(out_dir.glob("*.png"))
        ctx.log("OK", "visual", f"  captured {len(screenshots)} screenshots → {out_dir}")
    elif ctx.runner.has("aquatone"):
        ctx.log("INFO", "visual", "aquatone (fallback)…")
        rc, out, _ = ctx.runner.run(
            ["aquatone", "-out", str(out_dir), "-threads", str(max(1, min(int(getattr(ctx, "threads", 5)), 20))),
             "-silent", "-chrome-path", "/usr/bin/chromium"],
            timeout=1800, log_name="aquatone",
            input_data="\n".join(alive[:max_hosts])
        )
    else:
        ctx.log("WARN", "visual",
                "no screenshot tool installed (try: go install github.com/sensepost/gowitness@latest)")
