# Bundled third-party notices

This inventory is based on `requirements.lock` and the notices included in this
distribution. Preserve the notices inside the wheels and under `vendor/licenses`.
The table does not relicense dependencies or establish that TBHM's original
source has an open-source license. Project rights are addressed in `NOTICE.md`.

| Component | Locked version | Bundled notice | Recorded license information |
| --- | --- | --- | --- |
| certifi | 2026.7.22 | `vendor/licenses/certifi/LICENSE` | Mozilla certificate-bundle notice; MPL-2.0 reference |
| charset-normalizer | 3.5.2 | `vendor/licenses/charset-normalizer/LICENSE` | MIT |
| idna | 3.20 | `vendor/licenses/idna/LICENSE.md` | BSD-3-Clause |
| ldap3 | 2.9.1 | `vendor/licenses/ldap3/LICENSE.txt`, `COPYING.LESSER.txt`, `COPYING.txt` | LGPL-3.0-or-later, with accompanying texts |
| numpy | 2.3.5 | `vendor/licenses/numpy/LICENSE.txt` | BSD-3-Clause and additional bundled-library notices |
| psutil | 7.2.2 | `vendor/licenses/psutil/LICENSE` | BSD-3-Clause |
| pyasn1 | 0.6.4 | `vendor/licenses/pyasn1/LICENSE.rst` | BSD-2-Clause |
| PyYAML | 6.0.3 | `vendor/licenses/PyYAML/LICENSE` | MIT |
| requests | 2.34.2 | `vendor/licenses/requests/LICENSE`, `NOTICE` | Apache-2.0 |
| urllib3 | 2.8.0 | `vendor/licenses/urllib3/LICENSE.txt` | MIT |
| Go standard library used by the optional executor | See `runtime.json` for the recorded build | `vendor/licenses/GO-LICENSE` | Go BSD-style notice |

The Go module in `tooling/go_executor/go.mod` declares Go 1.22 and has no
third-party module requirements. The recorded build version and the minimum
module declaration are different facts.

External scanner catalog entries describe integrations. They do not mean those
scanners are redistributed, installed, licensed by TBHM, or proven operational.
Review any separately added third-party templates, wordlists or code before
including them in a public release, and retain their applicable attribution.
