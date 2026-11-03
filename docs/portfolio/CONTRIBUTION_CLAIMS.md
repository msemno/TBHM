# Authorship, provenance and CV-safe claims

A portfolio should clearly identify what the repository owner implemented, independently tested, modified, integrated and merely imported. The supplied files describe inherited capabilities and release validation, but do not provide a complete personal contribution ledger for every source module.

## Contribution record template

| Work item | Original source / author | Your change / implementation | Evidence to attach | Status |
| --- | --- | --- | --- | --- |
| Phase dispatch | Verify from source history | Describe your actual changes | Commit/PR + regression test | Not populated |
| False-positive controls | Verify from source history | Describe exact parser/classifier improvement | Diff + negative test | Not populated |
| Proof and delivery | Verify from source history | Describe actual verifier/delivery changes | Code diff + tamper test | Not populated |
| Local AI integration | Verify from source history | Describe actual scheduler/advice change | Diff + fixture test | Not populated |
| Publication documentation | Documentation overlay supplied separately | Review/adapt and attribute accurately | New commit + review | Pending |

Never mark rows completed merely because corresponding files exist.

## Safe README / interview language

“Maintained and documented an integrated security-assessment codebase with conservative evidence handling and a reproducible offline release workflow” is viable **only if you actually performed those activities**. “Implemented the proof verifier” or “built all 145 assessment engines” requires specific authoring evidence. Distinguish synthetic local tests from client vulnerability disclosures.

## Licensing and source origin

The existing `NOTICE.md` states that the original project distribution had no project-level license. This documentation pack does not alter licensing or assert ownership. Review source rights and third-party attributions before selecting a license or inviting outside contributions.
