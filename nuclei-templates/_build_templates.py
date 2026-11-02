#!/usr/bin/env python3
"""
Writes the TBHM custom nuclei template set into nuclei-templates/tbhm/.
Run once; the resulting *.yaml are what nuclei loads via `-t`.

These intentionally target the LOW / INFO band the official templates often
skip or that hunters want flagged anyway: missing security headers, weak cookie
flags, version/tech disclosure, permissive CORS, exposed dotfiles/backups,
directory listing, and dangerous HTTP methods.
"""
from pathlib import Path

OUT = Path(__file__).resolve().parent / "tbhm"
OUT.mkdir(parents=True, exist_ok=True)

TEMPLATES: dict[str, str] = {}

# ── Security headers ──────────────────────────────────────────────────────────
TEMPLATES["headers-missing-hsts.yaml"] = r"""
id: tbhm-missing-hsts

info:
  name: Missing Strict-Transport-Security (HSTS) Header
  author: tbhm
  severity: low
  description: |
    The response over HTTPS does not set Strict-Transport-Security. Without HSTS,
    a user can be downgraded to plaintext HTTP by an active network attacker
    (sslstrip), exposing session cookies and traffic.
  remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
  reference:
    - https://owasp.org/www-project-secure-headers/#strict-transport-security
  tags: tbhm,headers,misconfig,hsts
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code >= 200 && status_code < 400"
      - type: word
        part: header
        words:
          - "strict-transport-security"
        case-insensitive: true
        negative: true
"""

TEMPLATES["headers-missing-csp.yaml"] = r"""
id: tbhm-missing-csp

info:
  name: Missing Content-Security-Policy Header
  author: tbhm
  severity: low
  description: |
    No Content-Security-Policy header is set. CSP is the primary defence-in-depth
    control against XSS and data-injection. Absence widens the blast radius of any
    reflected/stored XSS or third-party script compromise.
  remediation: "Define a restrictive Content-Security-Policy (start with default-src 'self')."
  reference:
    - https://owasp.org/www-project-secure-headers/#content-security-policy
  tags: tbhm,headers,misconfig,csp,xss
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code >= 200 && status_code < 400"
      - type: word
        part: header
        words:
          - "content-security-policy"
        case-insensitive: true
        negative: true
      - type: word
        part: header
        words:
          - "text/html"
        case-insensitive: true
"""

TEMPLATES["headers-missing-xfo.yaml"] = r"""
id: tbhm-missing-x-frame-options

info:
  name: Missing X-Frame-Options / frame-ancestors (Clickjacking)
  author: tbhm
  severity: low
  description: |
    The HTML response sets neither X-Frame-Options nor a CSP frame-ancestors
    directive, so it can be embedded in a hostile iframe and used for clickjacking
    or UI-redress attacks.
  remediation: "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'."
  reference:
    - https://owasp.org/www-community/attacks/Clickjacking
  tags: tbhm,headers,misconfig,clickjacking
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code >= 200 && status_code < 400"
      - type: word
        part: header
        words:
          - "text/html"
        case-insensitive: true
      - type: word
        part: header
        words:
          - "x-frame-options"
          - "frame-ancestors"
        case-insensitive: true
        condition: or
        negative: true
"""

TEMPLATES["headers-missing-content-type-options.yaml"] = r"""
id: tbhm-missing-x-content-type-options

info:
  name: Missing X-Content-Type-Options Header
  author: tbhm
  severity: info
  description: |
    X-Content-Type-Options: nosniff is absent, so browsers may MIME-sniff the
    response and treat it as a different content type, enabling some XSS vectors
    on user-controlled uploads or text endpoints.
  remediation: "Add: X-Content-Type-Options: nosniff"
  reference:
    - https://owasp.org/www-project-secure-headers/#x-content-type-options
  tags: tbhm,headers,misconfig
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code >= 200 && status_code < 400"
      - type: word
        part: header
        words:
          - "x-content-type-options"
        case-insensitive: true
        negative: true
"""

TEMPLATES["headers-missing-referrer-policy.yaml"] = r"""
id: tbhm-missing-referrer-policy

info:
  name: Missing Referrer-Policy Header
  author: tbhm
  severity: info
  description: |
    No Referrer-Policy is set. Sensitive URLs (tokens in query strings, internal
    paths) can leak to third parties via the Referer header on outbound links and
    resource loads.
  remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin"
  reference:
    - https://owasp.org/www-project-secure-headers/#referrer-policy
  tags: tbhm,headers,misconfig,info-leak
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code >= 200 && status_code < 400"
      - type: word
        part: header
        words:
          - "referrer-policy"
        case-insensitive: true
        negative: true
      - type: word
        part: header
        words:
          - "text/html"
        case-insensitive: true
"""

TEMPLATES["headers-missing-permissions-policy.yaml"] = r"""
id: tbhm-missing-permissions-policy

info:
  name: Missing Permissions-Policy Header
  author: tbhm
  severity: info
  description: |
    Permissions-Policy (formerly Feature-Policy) is not set, so powerful browser
    features (camera, microphone, geolocation, payment) are not explicitly
    restricted for the page and any embedded content.
  remediation: "Add a Permissions-Policy locking down unused features, e.g. geolocation=(), camera=()."
  reference:
    - https://owasp.org/www-project-secure-headers/#permissions-policy
  tags: tbhm,headers,misconfig
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code >= 200 && status_code < 400"
      - type: word
        part: header
        words:
          - "permissions-policy"
          - "feature-policy"
        case-insensitive: true
        condition: or
        negative: true
      - type: word
        part: header
        words:
          - "text/html"
        case-insensitive: true
"""

# ── Cookie flags ──────────────────────────────────────────────────────────────
TEMPLATES["cookie-missing-secure.yaml"] = r"""
id: tbhm-cookie-without-secure

info:
  name: Cookie Set Without Secure Flag
  author: tbhm
  severity: low
  description: |
    A Set-Cookie response sets a cookie without the Secure attribute. The cookie
    can be transmitted over plaintext HTTP, exposing it to network interception.
    (Heuristic: flags when no Set-Cookie line in the response carries 'secure'.)
  remediation: "Add the Secure attribute to all cookies; serve only over HTTPS."
  reference:
    - https://owasp.org/www-community/controls/SecureCookieAttribute
  tags: tbhm,cookie,misconfig
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      # A cookie is set ...
      - type: regex
        part: header
        regex:
          - "(?i)set-cookie:\\s*\\S+"
      # ... and no Set-Cookie line mentions 'secure' (RE2-safe negative match).
      - type: regex
        part: header
        negative: true
        regex:
          - "(?i)set-cookie:[^\\r\\n]*secure"
    extractors:
      - type: regex
        part: header
        group: 1
        regex:
          - "(?i)set-cookie:\\s*([^=;\\r\\n]+)="
"""

TEMPLATES["cookie-missing-httponly.yaml"] = r"""
id: tbhm-cookie-without-httponly

info:
  name: Cookie Set Without HttpOnly Flag
  author: tbhm
  severity: low
  description: |
    A Set-Cookie response sets a cookie without HttpOnly, so client-side
    JavaScript can read it. If the cookie is a session token, any XSS becomes a
    full session-hijack. (Heuristic: flags when no Set-Cookie line carries 'httponly'.)
  remediation: "Add HttpOnly to session and auth cookies."
  reference:
    - https://owasp.org/www-community/HttpOnly
  tags: tbhm,cookie,misconfig,xss
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)set-cookie:\\s*\\S+"
      - type: regex
        part: header
        negative: true
        regex:
          - "(?i)set-cookie:[^\\r\\n]*httponly"
    extractors:
      - type: regex
        part: header
        group: 1
        regex:
          - "(?i)set-cookie:\\s*([^=;\\r\\n]+)="
"""

# ── Version / tech disclosure ─────────────────────────────────────────────────
TEMPLATES["disclosure-server-version.yaml"] = r"""
id: tbhm-server-version-disclosure

info:
  name: Server Software Version Disclosure
  author: tbhm
  severity: info
  description: |
    The Server response header exposes the web-server product and version. This
    helps an attacker map the stack to known CVEs.
  remediation: "Strip or generalise the Server header at the edge."
  tags: tbhm,disclosure,fingerprint
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)server:\\s*[a-z\\-]+/[0-9]+\\.[0-9]+"
    extractors:
      - type: regex
        part: header
        group: 1
        regex:
          - "(?i)server:\\s*([^\\r\\n]+)"
"""

TEMPLATES["disclosure-powered-by.yaml"] = r"""
id: tbhm-x-powered-by-disclosure

info:
  name: Technology Disclosure via X-Powered-By / Framework Headers
  author: tbhm
  severity: info
  description: |
    The response leaks backend technology through X-Powered-By, X-AspNet-Version,
    X-AspNetMvc-Version, X-Generator, or X-Drupal-Cache headers — useful recon for
    targeting version-specific exploits.
  remediation: "Remove framework version headers in production."
  tags: tbhm,disclosure,fingerprint
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        condition: or
        regex:
          - "(?i)x-powered-by:\\s*\\S+"
          - "(?i)x-aspnet-version:\\s*\\S+"
          - "(?i)x-aspnetmvc-version:\\s*\\S+"
          - "(?i)x-generator:\\s*\\S+"
          - "(?i)x-drupal-cache:\\s*\\S+"
    extractors:
      - type: kval
        kval:
          - x_powered_by
          - x_aspnet_version
          - x_generator
"""

# ── CORS ──────────────────────────────────────────────────────────────────────
TEMPLATES["cors-reflected-origin.yaml"] = r"""
id: tbhm-cors-reflected-origin

info:
  name: CORS Reflects Arbitrary Origin
  author: tbhm
  severity: medium
  description: |
    The server reflects an attacker-supplied Origin into
    Access-Control-Allow-Origin. If Access-Control-Allow-Credentials is also true,
    a malicious site can read authenticated responses cross-origin.
  remediation: "Validate Origin against an allow-list; never reflect it blindly with credentials."
  reference:
    - https://portswigger.net/web-security/cors
  tags: tbhm,cors,misconfig
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "https://tbhm-evil.example.com"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "access-control-allow-origin: https://tbhm-evil.example.com"
        case-insensitive: true
    extractors:
      - type: kval
        kval:
          - access_control_allow_credentials
"""

TEMPLATES["cors-null-origin.yaml"] = r"""
id: tbhm-cors-null-origin

info:
  name: CORS Allows null Origin
  author: tbhm
  severity: medium
  description: |
    The server returns Access-Control-Allow-Origin: null. A 'null' origin can be
    forged by a sandboxed iframe or data: document, bypassing the intended
    same-origin restriction — especially dangerous with credentials allowed.
  remediation: "Never allow the literal 'null' origin."
  reference:
    - https://portswigger.net/web-security/cors
  tags: tbhm,cors,misconfig
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "null"
    matchers:
      - type: word
        part: header
        words:
          - "access-control-allow-origin: null"
        case-insensitive: true
"""

# ── Exposed files / dotfiles ──────────────────────────────────────────────────
TEMPLATES["exposed-env-file.yaml"] = r"""
id: tbhm-exposed-dotenv

info:
  name: Exposed .env Configuration File
  author: tbhm
  severity: high
  description: |
    A .env file is reachable over HTTP. These commonly contain database
    credentials, API keys, and app secrets.
  remediation: "Block dotfiles at the web server; never deploy .env to web roots."
  tags: tbhm,exposure,config,secret
  metadata:
    max-request: 2

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.local"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
      - type: regex
        part: body
        condition: or
        regex:
          - "(?m)^[A-Z0-9_]+=.+$"
          - "(?i)(APP_KEY|DB_PASSWORD|SECRET|API_KEY|AWS_ACCESS_KEY)="
      - type: word
        part: header
        words:
          - "text/html"
        case-insensitive: true
        negative: true
    extractors:
      - type: regex
        part: body
        regex:
          - "(?i)(DB_PASSWORD|SECRET[_A-Z]*|API_KEY|AWS_[A-Z_]+)=[^\\r\\n]+"
"""

TEMPLATES["exposed-git-config.yaml"] = r"""
id: tbhm-exposed-git-config

info:
  name: Exposed .git/config (Source Code Disclosure)
  author: tbhm
  severity: high
  description: |
    The .git/config file is accessible, indicating the whole .git directory is
    likely exposed. An attacker can reconstruct source code and history, often
    recovering hard-coded secrets.
  remediation: "Deny access to .git/; do not deploy VCS metadata to production."
  tags: tbhm,exposure,git,source
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
      - type: word
        part: body
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and
"""

TEMPLATES["exposed-ds-store.yaml"] = r"""
id: tbhm-exposed-ds-store

info:
  name: Exposed .DS_Store File (Directory Enumeration)
  author: tbhm
  severity: low
  description: |
    A macOS .DS_Store file is reachable. It encodes the names of files in the
    directory, leaking hidden paths and aiding further content discovery.
  remediation: "Remove .DS_Store files and block them at the web server."
  tags: tbhm,exposure,info-leak
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}/.DS_Store"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
      - type: word
        part: body
        words:
          - "Bud1"
"""

TEMPLATES["exposed-backup-files.yaml"] = r"""
id: tbhm-exposed-backup-archive

info:
  name: Exposed Backup / Archive File
  author: tbhm
  severity: medium
  description: |
    A common backup or archive filename is downloadable from the web root
    (e.g. backup.zip, www.tar.gz, site.sql). These frequently contain full source
    or database dumps.
  remediation: "Remove backups from web-accessible paths; deny archive extensions."
  tags: tbhm,exposure,backup
  metadata:
    max-request: 6

http:
  - method: GET
    path:
      - "{{BaseURL}}/backup.zip"
      - "{{BaseURL}}/backup.tar.gz"
      - "{{BaseURL}}/www.zip"
      - "{{BaseURL}}/site.sql"
      - "{{BaseURL}}/database.sql"
      - "{{BaseURL}}/{{Hostname}}.zip"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
      - type: word
        part: header
        condition: or
        words:
          - "application/zip"
          - "application/x-gzip"
          - "application/gzip"
          - "application/octet-stream"
          - "application/sql"
      - type: dsl
        dsl:
          - "content_length > 0"
"""

TEMPLATES["exposed-phpinfo.yaml"] = r"""
id: tbhm-exposed-phpinfo

info:
  name: Exposed phpinfo() Page
  author: tbhm
  severity: medium
  description: |
    A phpinfo() page is publicly reachable, disclosing PHP version, loaded
    modules, environment variables, absolute paths, and sometimes secrets.
  remediation: "Remove phpinfo pages from production."
  tags: tbhm,exposure,phpinfo,disclosure
  metadata:
    max-request: 3

http:
  - method: GET
    path:
      - "{{BaseURL}}/phpinfo.php"
      - "{{BaseURL}}/info.php"
      - "{{BaseURL}}/test.php"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
      - type: word
        part: body
        words:
          - "PHP Version"
          - "phpinfo()"
        condition: or
"""

# ── Directory listing ─────────────────────────────────────────────────────────
TEMPLATES["misc-directory-listing.yaml"] = r"""
id: tbhm-directory-listing

info:
  name: Directory Listing Enabled
  author: tbhm
  severity: low
  description: |
    The server returns an auto-generated directory index, exposing the file
    structure and potentially sensitive files not meant to be linked.
  remediation: "Disable autoindex / directory browsing."
  tags: tbhm,misconfig,exposure
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        condition: or
        words:
          - "Index of /"
          - "<title>Directory listing for"
          - "[To Parent Directory]"
      - type: dsl
        dsl:
          - "status_code == 200"
"""

# ── Dangerous HTTP methods ────────────────────────────────────────────────────
TEMPLATES["method-trace-enabled.yaml"] = r"""
id: tbhm-http-trace-enabled

info:
  name: HTTP TRACE Method Enabled (Cross-Site Tracing)
  author: tbhm
  severity: low
  description: |
    The server answers TRACE, reflecting the request back. Combined with another
    flaw this enables Cross-Site Tracing (XST) to read headers/cookies that are
    otherwise HttpOnly.
  remediation: "Disable the TRACE method at the web server."
  reference:
    - https://owasp.org/www-community/attacks/Cross_Site_Tracing
  tags: tbhm,misconfig,method
  metadata:
    max-request: 1

http:
  - method: TRACE
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
      - type: word
        part: body
        words:
          - "TRACE /"
        case-insensitive: true
"""

TEMPLATES["method-options-allow.yaml"] = r"""
id: tbhm-http-options-write-methods

info:
  name: Write HTTP Methods Advertised via OPTIONS
  author: tbhm
  severity: info
  description: |
    The OPTIONS response advertises state-changing methods (PUT, DELETE, PATCH).
    If any are reachable unauthenticated, they may allow file upload or
    modification — worth manual verification.
  remediation: "Restrict the Allow set to required methods and enforce auth."
  tags: tbhm,misconfig,method
  metadata:
    max-request: 1

http:
  - method: OPTIONS
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)allow:\\s*[^\\r\\n]*(PUT|DELETE|PATCH)"
    extractors:
      - type: kval
        kval:
          - allow
"""

# ── Verbose errors ────────────────────────────────────────────────────────────
TEMPLATES["disclosure-stack-trace.yaml"] = r"""
id: tbhm-verbose-error-stacktrace

info:
  name: Verbose Error / Stack Trace Disclosure
  author: tbhm
  severity: low
  description: |
    An induced error response leaks a framework stack trace or debug page,
    revealing file paths, library versions, and sometimes query fragments.
  remediation: "Disable debug mode in production; return generic error pages."
  tags: tbhm,disclosure,debug,error
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}/%27%22%3E%5C"
    matchers:
      - type: word
        part: body
        condition: or
        case-insensitive: true
        words:
          - "Traceback (most recent call last)"
          - "Whoops, looks like something went wrong"
          - "java.lang."
          - "System.Web.HttpException"
          - "org.springframework"
          - "Warning: include("
          - "Fatal error:"
          - "DEBUG = True"
"""

# ── security.txt (informational hygiene) ──────────────────────────────────────
TEMPLATES["misc-missing-security-txt.yaml"] = r"""
id: tbhm-missing-security-txt

info:
  name: Missing security.txt
  author: tbhm
  severity: info
  description: |
    No /.well-known/security.txt is published. Not a vulnerability, but its
    absence means no machine-readable disclosure contact — useful context for a
    report and an easy hygiene win.
  remediation: "Publish /.well-known/security.txt per RFC 9116."
  reference:
    - https://www.rfc-editor.org/rfc/rfc9116
  tags: tbhm,info,hygiene
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}/.well-known/security.txt"
    matchers:
      - type: dsl
        dsl:
          - "status_code == 404 || status_code == 403"
"""

# Write them all
written = 0
for name, body in TEMPLATES.items():
    (OUT / name).write_text(body.lstrip("\n"))
    written += 1

print(f"wrote {written} templates to {OUT}")
