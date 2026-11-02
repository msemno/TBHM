
---
# Patch set — revision 2 (audit-driven corrections)

Applied after an independent review of revision 1. Changes:

## Takeover fix rewritten (phases/nuclei_extended.py)
Rev1 wrote finding_class/validation_required onto EVERY nuclei finding and used a
bare boolean `True`. Corrected:
- Lead metadata is added ONLY to takeover findings; all other findings are returned
  unmodified (no stray validation_required=False on normal results).
- validation_required is now descriptive TEXT, not `True`.
- ALL severities of a banner-only takeover are downgraded (not just HIGH/CRITICAL);
  MEDIUM takeovers now become LOW leads too.
- Real CVE guard implemented: a template tagged cve (or CVE-* id) is never
  downgraded even if it also carries a takeover tag.

## --resume invalidation widened (tbhm.py)
Rev1 only re-ran the core report phases. Added the remaining downstream phases that
read the whole findings DB so a resumed run doesn't leave them stale:
attack_path, compliance_coverage, coverage_map, playbook_integration,
data_analysis_intelligence, ai_supervision, llm_run_analysis, local_llm_triage,
vulnerability_intelligence_enrichment, execution_orchestration_plan.

## Scope-widening fix (core/targets.py)
target_scope_allows() previously fell through to "allow any host sharing the
registrable root" even when scope passed, and with NO allowlist an exact target
(api.example.com) silently authorized siblings (admin.example.com) and the apex.
Corrected:
- An explicit --scope allowlist is now the SOLE authority (no root fallback re-adds
  hosts it denied).
- Without an allowlist, only the exact configured targets and their subdomains are
  authorized — never the bare registrable root or arbitrary siblings.

## Packaging
- RELEASE_MANIFEST-v4.0.0.json regenerated (hashes/sizes/counts match; FIXES file
  listed). Package verifier passes.
- Archive repackaged inside the TBHM-v4.0.0-unified-safe/ root folder.

---
# Patch set — revision 3 (smart_crawl scope centralization)

## smart_crawl now uses the single scope authority (phases/smart_crawl.py)
Was: smart_crawl had its own _in_scope() keyed on registrable ROOT domains and made
raw requests.get calls; it would authorize any host under the apex (admin.example.com
from an api.example.com program) and disagreed with core.targets.target_scope_allows.
The headless (Playwright) pass recorded EVERY browser-contacted URL — analytics, CDNs,
OAuth, third-party APIs — into the application graph with no scope check.
Now:
- The crawl loop gates on core.targets.target_scope_allows(ctx, url) — the same
  decision the rest of TBHM uses.
- The headless pass scope-filters every observed URL through the same authority before
  recording it, so out-of-scope third parties no longer enter the graph as targets.
- _in_scope() is retained only as a deprecated compatibility shim.
NOTE: this does not yet implement Playwright page.route request BLOCKING (the browser
can still contact third parties during page load); that remains a separate milestone.
It does stop those URLs from being treated as in-scope discoveries.
Regression test: tests/test_patch_regressions.py::test_smart_crawl_uses_central_scope.

---
# Patch set — revision 4 (exact vs wildcard scope typing)

## Typed scope grammar (core/scope.py)
Added an EXACT host type while keeping every existing form byte-for-byte identical.
Grammar now:
  =api.example.com   EXACT — matches ONLY that host (no subdomains, no apex). Use
                     when a program lists a single hostname as its own asset.
  *.example.com      WILDCARD — any subdomain, NOT the bare apex (HackerOne
                     semantics). Verified already-correct; unchanged.
  .example.com       apex + subdomains (explicit form of the default).
  example.com        BARE default — apex + subdomains, subdomain-inclusive.
                     UNCHANGED, so existing scope files (Twilio/Sephora) behave
                     exactly as before.
  static*.example.com  '*' glob inside a label — unchanged; composes with the above.
The '=' marker works in --exclude too (=admin.example.com excludes only that host).
Because all phases route scope through core.targets.target_scope_allows ->
Scope.allows (incl. smart_crawl since rev3), the exact type governs the whole tool
— crawlers, tool target generation, and finding storage — not just one phase.
Backward compatible: no existing pattern changes meaning; '=' is a new marker.
Regression test: tests/test_patch_regressions.py::test_scope_exact_vs_wildcard_typing.
