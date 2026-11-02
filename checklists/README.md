# Checklists

The master methodology checklist lives in `/CHECKLIST.md` at the repo root.

This folder is reserved for **per-program custom checklists** you build
yourself. For example:

```
checklists/
├── README.md                  ← this file
├── anthropic.md               ← your notes from the Anthropic HackerOne program
├── atlassian.md               ← endpoints + edge cases specific to atlassian.net
└── stripe.md                  ← payment-related logic patterns
```

When you find a recurring pattern (e.g. "every Anthropic subdomain has a
proxy at /api/proxy/* that's worth probing"), drop a note here so future
scans don't re-discover from scratch.

The `knowledge.py` engine (`core/knowledge.py`) reads this folder
opportunistically — if a checklist file matches your current target's host,
its bullets are surfaced in the dashboard's "Hunt notes" panel.
