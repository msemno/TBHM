# TBHM v3.8 — Additive Safe Capability Expansion

## Added

- External perimeter evidence adapters.
- Static reverse-engineering adapters and normalized result import.
- Privilege-escalation audit result normalization.
- Advanced internal/AD assessment evidence normalization.
- Unified SAST/SCA/secret/IaC local orchestration and result import.
- New CLI flags and authorized-redteam profile registration.

## Preserved

No previous phase, profile, payload, template, report path or safety gate was removed. The new phases are additive and use the same `ctx.save_finding`, evidence, validation and reporting architecture.

## Safety boundaries

The release does not automate phishing credential capture, MFA interception, credential dumping, password spraying, NTLM poisoning/relay, pass-the-hash, ticket forgery, remote execution, persistence, C2, covert tunneling, destructive exploitation, kernel exploitation, DCShadow, malware execution or process injection.
