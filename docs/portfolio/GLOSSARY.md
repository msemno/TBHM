# Security-engineering glossary

**Phase:** A named unit in the dispatcher; registration does not mean an external action ran successfully.

**Native analysis:** Inspection performed within TBHM's own codebase and declared local-analysis contracts.

**External adapter:** A bridge to a separately installed executable, browser or scanner with its own constraints.

**Finding lead:** A potential issue based on preliminary observation, needing independent confirmation.

**Proof contract:** Class-specific rules the evidence verifier applies before automatic confirmation.

**Negative control:** A deliberately chosen case where the alleged failure should *not* occur, used to discriminate between expected and unexpected behavior.

**Repeat capture:** A new independently captured observation, not reusing the original result.

**Execution ledger:** Record of what phases and tools were attempted, blocked, failed or completed.

**Coverage gap:** Work that was not executed or not conclusive; should not be collapsed into “no vulnerabilities”.

**Delivery snapshot:** Reviewed report/evidence output and hashes, separate from sensitive live working state.

**Manifest:** File inventory with hashes and modes used by the release verifier. Not a cryptographic third-party signature.

**SBOM:** Software Bill of Materials; a structured inventory of known software components.

**Gitleaks finding:** A pattern detection that requires contextual review, and does not automatically prove a live credential leak.
