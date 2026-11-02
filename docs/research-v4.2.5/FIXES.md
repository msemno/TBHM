# Reproduced corrections

`SECURITY_BEFORE.json` and `SECURITY_AFTER.json` run the same harmless probes against the original baseline and the candidate. Unscoped private retrieval/history, trusted labeling of run data, proposal parent-path decisions, and manifest-less core installation are accepted by the baseline and refused by the candidate. The three defect areas are context privacy, proposal paths and installer integrity.

Generic ZIP/APK and source-tree analysis retain their historical contracts. Only core installation and release packaging require the new nonempty-manifest option. No global scanner/browser wire-traffic claim is introduced.
