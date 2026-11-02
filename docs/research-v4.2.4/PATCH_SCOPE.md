# Source patch scope

`changes.patch` is a Git-format binary-capable patch from 4.2.3 to 4.2.4. It
includes runtime code, CLI/phase hooks, version/installer/SBOM, tests and their
synthetic SQLite/TLS fixtures, examples, engineering documentation and ledgers.
The bundled TLS key is a public test fixture for loopback tests, never a
production identity. Dependencies and optional executables are unchanged.

Generated release manifests, test/evaluation/verification records, source
inventory and the patch itself are excluded to avoid recursive/self-referential
content. Those complete records are delivered separately inside this archive and
covered by the current release manifest. No source file is removed. The complete
source distribution is the primary deliverable; the patch is for review.
