# TBHM v3.9.7.5 JavaScript Intelligence

## Goal

After Katana, ParamSpider, ZAP and the built-in crawler finish, TBHM builds one
canonical inventory of every JavaScript URL they discovered. It does not select
only a small filename sample. Every unique in-scope candidate receives an
explicit result.

## Inputs

The aggregator reads, where present:

- `recon/javascript.txt` and historical crawler URL inventories;
- `recon/katana_urls.txt`, Katana JSONL and Katana logs;
- `recon/paramspider_urls.txt`;
- `recon/zap_urls.txt`;
- ZAP JSON, XML, HAR and SARIF evidence imported by `web_scanner_tooling`;
- ZAP AJAX-spider URLs when explicitly enabled;
- operator-supplied paths through `--js-candidate-results`.

URLs are canonicalized and deduplicated while preserving all discovery-source
provenance.

## Per-file processing

Each record receives one of these states:

- `analyzed`;
- `inaccessible` / `inaccessible_http`;
- `skipped_out_of_scope`;
- `skipped_operator_limit` when a nonzero `--js-max-files` cap is supplied;
- `skipped_size_limit`;
- an explicit source-map or recovered-source limit state.

No candidate is silently dropped after it enters the canonical inventory.

For fetched content, TBHM records:

- final URL and redirect chain;
- response status and content type;
- SHA-256, size, lines and entropy;
- framework/bundler hints;
- API paths, full URLs and parameters;
- GraphQL operations;
- authentication, cloud/service, WebSocket and feature/debug indicators;
- redacted secret candidates;
- browser-controlled sources and dangerous DOM/code/navigation sinks;
- explainable static JavaScript source-to-sink leads;
- source-map references;
- a usefulness score, classification and human-readable reasons.

## Source-map recovery

TBHM supports:

- remote `sourceMappingURL` references;
- inline `data:` source maps;
- `sourcesContent` extraction;
- analysis of each recovered original source;
- feedback of recovered endpoints and parameters into recon evidence.

Remote maps remain subject to scope, response-size, timeout and count policies.
Recovered sources beyond configured bounds are recorded as explicitly skipped.

## Main options

```text
--js-candidate-results PATH
--js-candidate-scan-files N
--js-max-files N
--js-max-bytes BYTES
--js-timeout SECONDS
--js-max-source-maps N
--js-max-recovered-sources N
--zap-max-targets N
--zap-timeout SECONDS
--no-zap-ajax-spider
```

`--js-max-files 0` means all discovered candidates and is the default. Per-file response size, timeout, scope and rate limits still protect the target and analyst environment. Set a nonzero count cap only when deliberately constraining a very large run; the index shows exactly what was not processed and why.

## Outputs

- `js_analysis/JS_USEFULNESS_INDEX.json`
- `js_analysis/js-usefulness.csv`
- `js_analysis/JS_ANALYSIS_SUMMARY.md`
- `js_analysis/files/*.json`
- `js_analysis/source_maps/*`
- `js_analysis/recovered_sources/*`
- updated `recon/js_endpoints.txt`
- updated `recon/js_parameters.txt`

Static JavaScript paths and secret candidates remain leads until manually or
runtime-validated in an authorized environment.
