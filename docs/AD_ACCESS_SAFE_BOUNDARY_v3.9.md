# AD Access Assessment — Safe Boundary

`ad_access_assessment` adds meaningful Active Directory review without turning TBHM into an autonomous domain-compromise framework.

## Live operations allowed

- Bounded TCP service/version checks against explicitly supplied DC IPs.
- Read-only Nmap `smb2-security-mode` review.
- Authenticated read-only LDAPS queries using a password held in an environment variable and certificate validation against the system trust store or `--ad-ldap-ca-file`.
- Inventory of:
  - accounts with SPNs;
  - accounts that do not require Kerberos pre-authentication;
  - unconstrained/constrained/resource-based delegation settings;
  - `PASSWD_NOTREQD` and non-expiring password exceptions;
  - domain password-policy attributes.

These are configuration observations. They are saved as leads because the phase does not retrieve tickets, validate passwords, or prove privilege escalation. Standard BloodHound/SharpHound JSON/ZIP can also feed the existing `lateral_movement_paths` phase for deterministic, read-only shortest-path exposure analysis; no path is executed.

## Import support

Use `--ad-access-results` for existing authorized exports from BloodHound/SharpHound (ZIP or extracted JSON), LDAPDomainDump, ADRecon, LDAP/LDIF, Nmap, and compatible JSON/JSONL/SARIF/CSV/XML/HTML/text assessment tools. Imports are bounded for laptop safety.

```bash
export TBHM_AD_PASSWORD='read-only-bind-password'

./tbhm.py -d corp.local -y \
  --profile authorized_redteam --redteam \
  --ad-access \
  --dc-ip 10.10.10.10 \
  --ad-domain corp.local \
  --ad-user 'audituser@corp.local' \
  --ad-password-env TBHM_AD_PASSWORD \
  --ad-ldaps \
  --ad-ldap-ca-file /path/to/internal-ca.pem
```

Import-only example:

```bash
./tbhm.py -d corp.local -y \
  --ad-access-results /path/to/approved/ad-exports \
  --phases ad_access_assessment,report
```

DC IPs are filtered through the existing `--scope`/`--exclude` policy and, when supplied, `--corp-cidr` networks.

## Operations explicitly excluded

TBHM does not automate:

- Responder/Inveigh poisoning or credential capture;
- NTLM relay;
- Kerberoasting or AS-REP ticket retrieval;
- password/hash cracking or wordlist escalation;
- pass-the-hash/pass-the-ticket;
- WMI, WinRM, SMB, service, scheduled-task, or PowerShell remote command execution;
- DCSync, NTDS/LSASS/secrets dumping, krbtgt extraction, or ticket forgery;
- Metasploit, Meterpreter, reverse shells, bind shells, C2, persistence, tunneling, or payload hosting;
- AMSI/EDR bypass, obfuscation, or evasion;
- disabling `safe_writes.py`, hard caps, authorization checks, or scope enforcement.

Where those paths are in the rules of engagement, TBHM records them as manual/high-risk approval items or imports separately collected evidence. It does not execute them.
