# Runtime validation

Environment: development Linux x86-64, CPython 3.12.14, exact bundled core wheels.
This is not the user's Kali VM or Windows GPU host. No VM/GPU throughput claim is
made. Thresholds were fixed by executable fixtures before candidate comparison:
owned child cancellation/duplex timeout under three seconds, interrupted CLI
partial reporting under eight seconds, finite phase dispatch and bounded runtime
embedding batches. Failed exploratory attempts are retained separately; they were
not counted as accepted results. Final completion receipts bind to the tested build.

Controlled measurements in validation/performance.json:

| Operation | Original 4.2.5 | Corrected 4.2.6 |
|---|---:|---:|
| Append 1,000 blocked events and flush final ledger | 6.758090 s | 0.561001 s |
| Persisted ledger files after final flush | 170,071 bytes | 442,747 bytes |
| Redact a benign 1-MiB line, mean of three runs | 0.721662 s | 0.049579 s |
| Microbenchmark process peak RSS | 14,592 KiB | 15,856 KiB |

The journal intentionally uses more final disk space to avoid repeated full-array
serialization and preserve recovery. Required-literal guards skip impossible
provider-regex matches while unknown rules continue to execute; secret/canary
regressions still pass. These are small local microbenchmarks, not statistically
representative workload or latency guarantees.

Retained CLI fixture phase-loop wall times were 1.887 seconds for vulnerable
BOLA, 2.532 for patched BOLA, 1.688 for public/inconclusive BOLA and 0.356 for the
interrupted content-discovery fixture. These exclude startup and final sealing;
the CLI cancellation assertion separately includes partial-report completion.
The owned TERM-ignoring child is killed while an unrelated owned fixture process
survives. Both Python and bundled Go executor contracts are exercised. Output
redaction, full duplex, blocked input and inherited offline filtering are tested.

Runtime vector tests demonstrate an eight-row bounded batch, persisted backlog
recovery without new artifacts, zero dispatch after cancellation, finite/dimension
checks, explicit incompatible-space deferral and successful-row retention after
a later failure. The original 32,762-row database was absent and was not drained.

Still required on the user's topology: whole-run CPU/RAM/child/disk peaks, actual
model throughput/VRAM, scanner versions/templates, long response/streaming stress,
Windows supervision and recovery under VM suspend/network loss. No timing claim
here converts socket/dispatch deadlines into an arbitrary CPU/wire sandbox.
