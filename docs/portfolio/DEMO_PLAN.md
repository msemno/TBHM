# Planned synthetic demonstration — not yet implemented

The reference portfolio (`pentest-portfolio-labs`) is easy to evaluate because it includes runnable, local, deliberately vulnerable/fixed fixtures and a clearly explained manual report. TBHM is much larger; duplicating its folder hierarchy would not reproduce that clarity. A **small self-contained synthetic demo** is a better bridge between TBHM's architecture and an evaluator's understanding.

## Proposed demonstrator (future separate work)

**Goal:** demonstrate how an observation becomes a lead or confirmed finding under a supported proof contract, including *negative controls* and *incomplete runs*.

1. Define a loopback-only synthetic API and two test actors with synthetic authorization tokens.
2. Construct a normal-control case and one controlled cross-actor access defect. Use only a non-production fixture.
3. Run the minimal declared TBHM phases with explicit local scope and bounded requests. Capture exact invocation and tool availability.
4. Verify whether the selected proof-v2 contract is actually invoked and its conditions satisfied, or document why not.
5. Show separate `execution_ledger.json`, leads and confirmed outputs. Provide sanitized excerpts only.
6. Retest a corrected fixture and show the defect no longer meets the positive proof conditions.
7. Publish no raw tokens, private local keys, captures from real users or fabricated scores.

## Acceptance criteria for calling the demo complete

- [ ] Local fixture source and run configuration committed.
- [ ] Successful and failing control runs independently reproducible.
- [ ] Real TBHM commands, package version and dates recorded.
- [ ] Clean sample evidence with no private information.
- [ ] Proof classification agrees with actual verifier output.
- [ ] Negative tests prevent promoting scanner prose to confirmed findings.
- [ ] A new CI workflow has been designed and its actual run linked, if CI is claimed.

**Status: proposal only.** No LAB-001-equivalent demonstration has been generated or executed by this documentation pack.
