# Regression fixture isolation — TBHM 4.2.5

## Operator report

The supplied Kali log recorded 70/72 passing script groups, no required doctor failures, 20 optional failures and an uninitialized AI home. Installed executable paths are inventory evidence, not adapter validation. Ollama was not checked by the offline doctor.

## Reproduced causes and narrow changes

1. `test_valid_empty_and_malformed_template_stores` redirected template directories but still allowed the production `nuclei -tl -silent` fallback to read the operator's real templates. A mocked external listing reproduced the incorrect nonzero result from an otherwise empty test store. The fixture now isolates that listing. An additional test verifies that a successful CLI fallback is counted and a failed listing contributes zero. Production Nuclei discovery is unchanged.
2. The combined local workflow fixture inherited the entire host PATH. A deliberately injected failing `semgrep` reproduced exit code 2 with the same three-finding summary seen in the supplied log. This demonstrates one possible environmental cause; the log alone does not identify the actual failing analyzer on the user's VM. The fixture now uses an empty PATH for built-in/local-model checks, while invoking Python by its absolute path. A separate failing-analyzer fixture explicitly checks `tool-error`, run `incomplete`, nonzero exit and a valid sealed report. Production adapter errors remain visible.

No scanner phase identity, CLI contract, proof authority or runtime success criterion changes in this regression fix. Existing installer progress/checkpoint and ParamSpider source fixes remain included.

## Re-run on Kali

Use Python 3.12 and install this archive into a separate directory so the existing installation and outputs remain available. For example, after downloading the ZIP:

```bash
mkdir -p "$HOME/tools/tbhm-regression-fix"
unzip "$HOME/Downloads/TBHM-4.2.5-kali-regression-fixes.zip" \
  -d "$HOME/tools/tbhm-regression-fix"
cd "$HOME/tools/tbhm-regression-fix/TBHM-4.2.5"
bash install.sh --offline --python /usr/bin/python3.12
.venv/bin/python scripts/run_tests.py --workers 1 \
  --output "$HOME/tbhm-work/regression-v4.2.5-fixed.json"
.venv/bin/python scripts/validate_v4_release.py
```

If the user's Python 3.12 is managed by uv rather than `/usr/bin/python3.12`, use the actual executable shown by `uv python find 3.12` in `--python`. Do not substitute Python 3.13/3.14 into this offline wheel distribution. Use the extracted directory in subsequent AI commands, rather than the older `~/tools/TBHM-4.2.5` path shown in the guide.

The regression suite does not certify third-party binaries, a live target, real model quality, or the user's VM performance. A genuine external-tool error during an ordinary scan still requires investigation in `execution_ledger.json`; the test fixture change does not repair or conceal that tool failure.

See `AI-SETUP-KALI-v4.2.5.md` for the next installation and real-inference checks. The release includes code and dependencies for the core, not preloaded LLM weights.
