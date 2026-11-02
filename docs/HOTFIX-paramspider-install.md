# TBHM 4.2.5 ParamSpider installer correction — 20 October 2026

The original `tooling/tool_catalog_v3975.json` recipe used `pipx install paramspider`. The PyPI project with that name is a quarantined, nonfunctional placeholder. A selected or `all-safe` catalog installation therefore failed with `No matching distribution found for paramspider`.

This correction changes only that recipe to the upstream repository: `pipx install git+https://github.com/devanshbatham/ParamSpider.git`. The existing installer continues to create one isolated virtual environment under `~/.local/share/tbhm-tools/venvs/paramspider`, install through its Python interpreter, and expose `~/.local/bin/paramspider`. The optional source fetch requires `git` and network access. Avoid the quarantined PyPI distribution.

From the extracted release directory, plan and install this one integration:

```bash
.venv/bin/python scripts/install_extended_tools.py --tools paramspider --json
.venv/bin/python scripts/install_extended_tools.py --tools paramspider --apply --json
"$HOME/.local/bin/paramspider" -h
```

If an existing installation produced the reported error, it left a virtual environment but did not create the success marker. The corrected installer can reuse that directory; it will retry the upstream source install. Do not remove other virtual environments or force a system-level Python install.

An isolated offline regression verifies the catalog source spec, generated installer command, executable link and success marker. The dry-run plan was executed against the corrected catalog. Live installation from GitHub and operation on the user's Kali VM are **not verified** from this environment. The historical `docs/research-v4.2.5` validation reports predate this single-recipe correction; use this note and the regenerated release manifest for its scope.
