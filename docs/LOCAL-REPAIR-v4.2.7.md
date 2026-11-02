# TBHM 4.2.7 local regression-environment repair

This follow-up repairs defects in the regression harness, plus friendly input-file errors. It does not reinstall the tool, reset AI memory, change your model, stop Ollama/SSH, alter proof rules, or disable failing tests.

## Why the operator saw 83/87

- The compatibility probe inherited `TBHM_LOCAL_LLM_MODEL=qwen2.5:1.5b` and compared that effective user override to the frozen canonical default. The application was honoring the setting; the test was not isolating it.
- Two local CLI workflow tests tried to isolate optional scanners by emptying PATH. Startup then prepended `~/go/bin` and `~/.local/bin`, allowing installed tools back in. A controlled failing Semgrep under a synthetic user home reproduced exactly those two exit-code-2 failures. Test processes now have private HOME/XDG/AI/tool state and explicitly respect the provided PATH. Ordinary scans keep the existing path discovery unless `TBHM_RESPECT_PATH=1` is explicitly requested.
- Two legacy AI tests referenced the real default Ollama port. A working or slow local service could change them from deterministic fallback tests into real embedding/advisory jobs. They now use an exclusively reserved private unavailable endpoint. Separate protocol-fixture tests continue to exercise generation, embedding and planner behavior.
- `~/audits/my-project/targets.txt` was an example path, not an automatically created input. Scope, exclusion and program-policy files must exist and describe the actual engagement. Missing files now return an actionable error before any scan instead of a traceback.

The original 29 focused cases passing on the operator's VM remain useful evidence. The complete 83/87 result was not a full pass and must not be relabeled as one. If any group still fails after this repair, retain its JSON/fixture diagnostics; do not remove the assertion or increase timeouts to make it green.

## Apply without reinstalling

Download `TBHM-4.2.7-Local-Repair.py` into Downloads. In Kali:

```sh
cd "$HOME/tools/TBHM-4.2.7"
.venv/bin/python "$HOME/Downloads/TBHM-4.2.7-Local-Repair.py" --tool-home "$PWD" --check
.venv/bin/python "$HOME/Downloads/TBHM-4.2.7-Local-Repair.py" --tool-home "$PWD" --apply
```

The repair requires the exact known file hashes, checks syntax, backs up every changed file and the current manifest outside the tool tree, regenerates a manifest for the local build, verifies it and prints its receipt. It refuses unknown modifications. Reapplying is idempotent. It does not auto-run a full scan. Use the printed receipt path with `--rollback RECEIPT` only if you deliberately want to undo the repair; no interactive blank receipt prompt is used.

Rerun the four failed groups first:

```sh
.venv/bin/python scripts/run_tests.py --source . --workers 1 --failures-from "$HOME/tbhm-work/full-regression-v427.json" --output "$HOME/tbhm-work/failed-groups-v427-recheck.json"
```

Then rerun all packaged groups:

```sh
.venv/bin/python scripts/run_tests.py --source . --workers 1 --output "$HOME/tbhm-work/full-regression-v427-recheck.json"
```

There is one additional regression module in the repaired tree. A whole-suite timeout is still a failure (124). The runner now stops its owned process group rather than leaving its fixture descendants behind. Existing default 110-second group limits were not raised.

The repair changes the executable source fingerprint. Historical validation receipts continue to identify their original build; they are not proof of the patched build. Keep old runs unchanged, use fresh output directories, and synchronize source knowledge once using the normal `--ai-sync-tool` operation after the model link is healthy. Do not reimport CVE/CWE data or redownload models for this repair.

## Prepare one real URL without placeholder files

These are individual terminal commands, compatible with Kali's zsh. Enter an actual authorized origin such as `https://your-authorized-host`, not the example words. Preserve the current program's stricter path, operation, rate and header conditions in its actual program-policy file before wider testing.

```sh
cd "$HOME/tools/TBHM-4.2.7"
printf 'Authorized target URL: '
IFS= read -r TBHM_TARGET
mkdir -p "$HOME/tbhm-work"
TBHM_WORK=$(mktemp -d "$HOME/tbhm-work/web-v427-XXXXXX")
.venv/bin/python -c 'import sys; from pathlib import Path; from urllib.parse import urlsplit; u=urlsplit(sys.argv[1]); valid=u.scheme in ("http","https") and bool(u.hostname) and not u.username and not u.password; valid or sys.exit("Use an authorized HTTP(S) URL without embedded credentials"); root=Path(sys.argv[2]); (root/"targets.txt").write_text(sys.argv[1]+"\n"); (root/"scope.txt").write_text("="+u.hostname.encode("idna").decode("ascii")+"\n"); (root/"exclude.txt").write_text("")' "$TBHM_TARGET" "$TBHM_WORK"
```

A small explicit-host starting check is:

```sh
./tbhm -l "$TBHM_WORK/targets.txt" --scope "$TBHM_WORK/scope.txt" --exclude "$TBHM_WORK/exclude.txt" --profile authorized_safe --quick --no-bootstrap -y --phases preflight,spec_scan,strict_finding_validation,test_coverage_ledger,report,evidence_finalize --rate-limit 1 --threads 1 --max-parallel-tools 1 -o "$TBHM_WORK/run"
```

Add `--program-policy /path/to/the-actual-reviewed-policy.json` when the engagement requires a policy. Do not create fictitious permission or policy contents to bypass an input error. A public page does not establish authorization for unrelated hosts or operations. This initial check is not an exhaustive website, mobile or business-logic assessment.
