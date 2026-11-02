"""Phase: interface_probe — additive read-only discovery of protocol/identity
interfaces called out in the field playbook that were not yet automated by TBHM.

Playbook coverage added (all read-only, non-destructive):
  - gRPC server reflection            (playbook §42.3)      -> BR10
  - Socket.IO transport handshake     (playbook §42.4)      -> BR10
  - AsyncAPI spec discovery           (playbook §42.5)      -> BR10
  - JSON:API + .well-known/host-meta  (playbook §42.6)      -> BR10
  - SAML metadata / SSO endpoints     (playbook §47 SAML)   -> BR30
  - SCIM provisioning endpoints       (identity federation) -> BR30
  - MCP endpoints + shadow-MCP hint   (playbook §50 agents) -> BR20

This phase never sends a mutating request. gRPC reflection uses `grpcurl list`
(read-only). Everything else is a GET or an OPTIONS. Nothing here brute-forces
credentials, alters state, or exfiltrates data — it only records that an
interface is *present and reachable* so the operator can validate authorization
and per-object/tenant checks manually (which the playbook's Section 4 loop
requires anyway).

Existing coverage is intentionally NOT duplicated:
SOAP/WSDL, XML-RPC, OData, JSON-RPC, GraphQL variants (phases/spec_scan.py),
WebSocket + SSE + LLM + webhooks (phases/api_specific.py), OpenAPI/Swagger
(phases/spec_scan.py) already exist and are left untouched.
"""
from __future__ import annotations

try:
    import requests
except ImportError:
    requests = None

from urllib.parse import urlparse

# ── path banks (GET-only discovery) ──────────────────────────────────────────
ASYNCAPI_PATHS = ["/asyncapi.json", "/asyncapi.yaml", "/asyncapi",
                  "/api/asyncapi.json", "/.well-known/asyncapi.json"]
SOCKETIO_PATH  = "/socket.io/?EIO=4&transport=polling"
JSONAPI_HINTS  = ["/api", "/api/v1", "/jsonapi", "/api/jsonapi"]
HOSTMETA_PATHS = ["/.well-known/host-meta", "/.well-known/host-meta.json"]
SAML_PATHS     = ["/saml/metadata", "/saml2/metadata", "/saml/metadata.xml",
                  "/simplesaml/saml2/idp/metadata.php", "/adfs/ls/",
                  "/FederationMetadata/2007-06/FederationMetadata.xml",
                  "/sso/saml/metadata", "/auth/realms/master/protocol/saml/descriptor"]
SCIM_PATHS     = ["/scim/v2/ServiceProviderConfig", "/scim/v2/Schemas",
                  "/scim/v2/ResourceTypes", "/Users", "/scim/v2/Users",
                  "/api/scim/v2/ServiceProviderConfig"]
MCP_PATHS      = ["/.well-known/mcp", "/.well-known/mcp.json", "/mcp",
                  "/mcp/manifest.json", "/api/mcp", "/mcp/sse", "/mcp/messages"]


def _rl_wait(ctx):
    rl = getattr(ctx, "ratelimit", None) or getattr(ctx, "rl", None)
    if rl and hasattr(rl, "wait"):
        try:
            rl.wait()
        except Exception:
            pass


def _get(ctx, url, timeout=8, headers=None, method="GET"):
    if not requests:
        return None
    _rl_wait(ctx)
    try:
        return requests.request(method, url, timeout=timeout, verify=False,
                                allow_redirects=False, headers=headers or {})
    except Exception:
        return None


def _finding(ctx, sev, title, target, url, desc, impact, remediation,
             evidence="", cwe="CWE-200", method="GET", score=25, branch=""):
    ctx.save_finding({
        "phase": "interface_probe", "severity": sev, "confidence": "MEDIUM",
        "title": title, "target": target, "url": url, "method": method,
        "evidence": (evidence or url)[:600],
        "description": desc, "impact": impact, "remediation": remediation,
        "cwe": cwe, "mrs_score": score,
        "playbook_branch": branch,
    })


# ── gRPC server reflection (read-only) ───────────────────────────────────────
def _grpc(ctx):
    if not (getattr(ctx, "runner", None) and ctx.runner.has("grpcurl")):
        return
    ports = []
    raw = getattr(ctx.args, "interface_grpc_ports", None)
    if raw:
        ports = [p.strip() for p in str(raw).split(",") if p.strip()]
    if not ports:
        ports = ["443", "50051"]  # https + grpc default; only probed on scoped hosts
    from core.targets import get_domains
    for d in get_domains(ctx)[:15]:
        host = urlparse(d).hostname or d.split("/")[0]
        for port in ports:
            tls = "-insecure" if port in ("443", "8443") else "-plaintext"
            cmd = ["grpcurl", tls, f"{host}:{port}", "list"]
            try:
                res = ctx.runner.run(cmd, timeout=25)
            except Exception:
                continue
            out = (getattr(res, "stdout", "") or "") if res else ""
            if out and "grpc.reflection" in out.lower() or (out and "." in out and "failed" not in out.lower()):
                svcs = [l.strip() for l in out.splitlines() if l.strip()][:20]
                _finding(
                    ctx, "MEDIUM", "gRPC server reflection enabled",
                    f"{host}:{port}", f"grpc://{host}:{port}",
                    "The gRPC server answered a reflection `list` call and exposed its "
                    "service list without authentication. Reflection lets a client "
                    "enumerate every method and message type. Manually verify per-method "
                    "authorization and tenant isolation on the exposed services.",
                    "Full service/method surface disclosure; aids authz-bypass and "
                    "excessive-data-exposure testing on individual RPCs.",
                    "Disable server reflection in production, or require authentication "
                    "before reflection. Enforce per-method authorization.",
                    evidence="Services: " + "; ".join(svcs), cwe="CWE-200",
                    score=45, branch="BR10",
                )


# ── Socket.IO handshake ──────────────────────────────────────────────────────
def _socketio(ctx):
    from core.targets import get_domains
    for d in get_domains(ctx)[:15]:
        url = f"https://{d}{SOCKETIO_PATH}"
        r = _get(ctx, url)
        if not r:
            continue
        body = r.text[:200] if hasattr(r, "text") else ""
        # Engine.IO open packet starts with "0{" and carries a session id ("sid").
        if r.status_code == 200 and ('"sid"' in body or body.startswith("0{")):
            _finding(
                ctx, "INFO", "Socket.IO transport reachable",
                d, url,
                "A Socket.IO/Engine.IO endpoint returned an open handshake packet "
                "with a session id. Verify the socket enforces origin checks and "
                "per-message authorization (send a privileged event with a low-priv "
                "token and confirm it is rejected).",
                "Potential auth/authorization bypass or cross-user event leakage over "
                "the realtime channel.",
                "Enforce CORS/origin allow-listing and per-message authorization; do "
                "not trust the connection handshake as authentication.",
                evidence=body, cwe="CWE-346", score=25, branch="BR10",
            )


# ── AsyncAPI spec discovery ──────────────────────────────────────────────────
def _asyncapi(ctx):
    from core.targets import get_domains
    for d in get_domains(ctx)[:15]:
        for path in ASYNCAPI_PATHS:
            url = f"https://{d}{path}"
            r = _get(ctx, url)
            if not r or r.status_code != 200:
                continue
            low = (r.text[:400] if hasattr(r, "text") else "").lower()
            if "asyncapi" in low and ("channels" in low or "servers" in low or '"asyncapi"' in low):
                _finding(
                    ctx, "LOW", "AsyncAPI specification exposed",
                    d, url,
                    "An AsyncAPI document is publicly readable. It documents the "
                    "event/message channels, brokers, and payloads of the async API "
                    "surface — a map for testing queue/webhook/event authorization.",
                    "Discloses the full asynchronous message surface (channels, "
                    "schemas, brokers) to an unauthenticated client.",
                    "Require authentication to fetch the AsyncAPI document, or host it "
                    "only in internal developer portals.",
                    evidence=low[:300], cwe="CWE-200", score=20, branch="BR10",
                )
                break


# ── JSON:API + host-meta discovery ───────────────────────────────────────────
def _jsonapi_hostmeta(ctx):
    from core.targets import get_domains
    for d in get_domains(ctx)[:15]:
        # JSON:API media type detection
        for path in JSONAPI_HINTS:
            url = f"https://{d}{path}"
            r = _get(ctx, url, headers={"Accept": "application/vnd.api+json"})
            if not r:
                continue
            ct = r.headers.get("Content-Type", "") if hasattr(r, "headers") else ""
            if "application/vnd.api+json" in ct:
                _finding(
                    ctx, "INFO", "JSON:API endpoint detected",
                    d, url,
                    "The endpoint responded with the JSON:API media type. JSON:API "
                    "exposes `include`, `fields[]`, `filter`, and `page` parameters — "
                    "test these for excessive data exposure, IDOR via resource ids, and "
                    "sparse-fieldset authorization bypass.",
                    "Structured resource API; risk of over-fetching or IDOR through "
                    "compound-document includes.",
                    "Enforce object-level authorization on every included resource and "
                    "on filter/sort parameters; do not rely on client-selected fields.",
                    evidence=f"Content-Type: {ct}", cwe="CWE-639", score=20, branch="BR10",
                )
                break
        # host-meta (RFC 6415) — can leak internal endpoints / XRD links
        for path in HOSTMETA_PATHS:
            url = f"https://{d}{path}"
            r = _get(ctx, url)
            if not r or r.status_code != 200:
                continue
            body = r.text[:400] if hasattr(r, "text") else ""
            if "xrd" in body.lower() or '"links"' in body.lower() or "<link" in body.lower():
                _finding(
                    ctx, "INFO", "host-meta document exposed",
                    d, url,
                    "A `.well-known/host-meta` document is readable and lists linked "
                    "resources (LRDD/XRD). Review the advertised links for internal or "
                    "unintended endpoints.",
                    "May advertise additional endpoints or metadata useful for surface "
                    "expansion.",
                    "Only publish host-meta if the protocol genuinely requires it; "
                    "review advertised links.",
                    evidence=body[:300], cwe="CWE-200", score=15, branch="BR10",
                )
                break


# ── SAML / SSO metadata ──────────────────────────────────────────────────────
def _saml(ctx):
    from core.targets import get_domains
    for d in get_domains(ctx)[:15]:
        for path in SAML_PATHS:
            url = f"https://{d}{path}"
            r = _get(ctx, url)
            if not r or r.status_code != 200:
                continue
            body = r.text[:500] if hasattr(r, "text") else ""
            low = body.lower()
            if "entitydescriptor" in low or "md:entitydescriptor" in low or "federationmetadata" in low:
                _finding(
                    ctx, "LOW", "SAML/SSO metadata endpoint exposed",
                    d, url,
                    "A SAML metadata / federation descriptor is publicly readable. It "
                    "reveals the IdP/SP entity id, ACS URLs, and signing certificates. "
                    "Manually validate: signed assertions required, audience/recipient "
                    "restriction enforced, and no XML-signature-wrapping or comment-"
                    "injection acceptance (playbook §47 SAML).",
                    "Discloses federation topology and certificates; feeds SAML "
                    "assertion/response validation testing.",
                    "Publishing SP/IdP metadata is often expected, but confirm the "
                    "consumer enforces signature validation, audience restriction, and "
                    "InResponseTo/replay checks.",
                    evidence=low[:300], cwe="CWE-347", score=30, branch="BR30",
                )
                break


# ── SCIM provisioning endpoints ──────────────────────────────────────────────
def _scim(ctx):
    from core.targets import get_domains
    for d in get_domains(ctx)[:15]:
        for path in SCIM_PATHS:
            url = f"https://{d}{path}"
            # SCIM discovery endpoints are GET; a 200/401/403 all confirm presence.
            r = _get(ctx, url, headers={"Accept": "application/scim+json"})
            if not r:
                continue
            ct = r.headers.get("Content-Type", "") if hasattr(r, "headers") else ""
            body = r.text[:300] if hasattr(r, "text") else ""
            scim_marker = ("application/scim+json" in ct
                           or "urn:ietf:params:scim" in body.lower())
            if scim_marker:
                if r.status_code == 200 and "serviceproviderconfig" in path.lower():
                    sev, score, extra = "MEDIUM", 45, (
                        " The ServiceProviderConfig was served WITHOUT authentication — "
                        "verify that Users/Groups provisioning endpoints are NOT similarly "
                        "unauthenticated (SCIM can create/modify identities).")
                    cwe = "CWE-306"
                elif r.status_code in (401, 403):
                    sev, score, extra = "INFO", 15, (
                        " Endpoint present and correctly requires authentication.")
                    cwe = "CWE-200"
                else:
                    sev, score, extra = "INFO", 20, ""
                    cwe = "CWE-200"
                _finding(
                    ctx, sev, "SCIM provisioning endpoint detected",
                    d, url,
                    "A SCIM 2.0 identity-provisioning endpoint is reachable." + extra +
                    " SCIM manages user/group lifecycle; unauthenticated or weakly-"
                    "scoped SCIM is a direct identity-takeover path. Confirm bearer-token "
                    "auth and tenant scoping on Users/Groups (BR30).",
                    "Identity provisioning surface; unauthorized access enables account "
                    "creation, privilege change, or enumeration.",
                    "Require a scoped bearer token on all SCIM resources; rate-limit; log "
                    "provisioning actions; isolate per tenant.",
                    evidence=f"HTTP {r.status_code}; CT: {ct}", cwe=cwe,
                    score=score, branch="BR30",
                )
                break


# ── MCP endpoints + shadow-MCP inventory ─────────────────────────────────────
def _mcp(ctx):
    from core.targets import get_domains
    hits = []
    for d in get_domains(ctx)[:15]:
        for path in MCP_PATHS:
            url = f"https://{d}{path}"
            r = _get(ctx, url)
            if not r:
                continue
            body = (r.text[:400] if hasattr(r, "text") else "").lower()
            ct = r.headers.get("Content-Type", "") if hasattr(r, "headers") else ""
            is_mcp = ("modelcontextprotocol" in body or '"tools"' in body
                      or '"mcpservers"' in body or "text/event-stream" in ct
                      and "mcp" in path)
            if is_mcp:
                hits.append((d, url))
                _finding(
                    ctx, "MEDIUM", "MCP (Model Context Protocol) endpoint exposed",
                    d, url,
                    "An MCP endpoint is reachable. MCP servers expose tools/resources an "
                    "AI agent can invoke. Manually verify: the server is inventoried and "
                    "authenticated, tools follow least privilege, human-approval gates "
                    "exist for sensitive actions, and this is not a shadow/untrusted MCP "
                    "server (playbook §50 agentic/MCP).",
                    "An exposed or unauthenticated MCP server can grant an attacker (or a "
                    "prompt-injected agent) access to whatever tools/data it brokers — "
                    "excessive agency and data leakage.",
                    "Authenticate MCP transports, inventory every MCP server, enforce "
                    "least-privilege tool scopes, and require human approval for "
                    "state-changing tools.",
                    evidence=f"CT: {ct}; body: {body[:200]}", cwe="CWE-284",
                    score=50, branch="BR20",
                )
                break
    if len(hits) > 1:
        _finding(
            ctx, "LOW", "Multiple MCP endpoints — confirm none are shadow MCP servers",
            "", "", 
            "More than one MCP endpoint was discovered across the scope: " +
            "; ".join(u for _, u in hits) + ". Reconcile this list against the approved "
            "MCP server inventory; any endpoint not on the inventory is a shadow MCP "
            "server and must not be trusted by agents.",
            "Shadow MCP servers expand agent tool access outside governance.",
            "Maintain an allow-list of approved MCP servers; block agent connections to "
            "unlisted endpoints.",
            evidence="; ".join(u for _, u in hits)[:500], cwe="CWE-284",
            score=25, branch="BR20",
        )


def run(ctx):
    if not requests:
        ctx.log("WARN", "interface_probe", "requests not installed; skipping")
        return
    if not ctx.profile.get("active_probes", True):
        ctx.log("INFO", "interface_probe", "passive profile; skipping active interface probes")
        return
    for fn, label in ((_grpc, "gRPC reflection"),
                      (_socketio, "Socket.IO"),
                      (_asyncapi, "AsyncAPI"),
                      (_jsonapi_hostmeta, "JSON:API/host-meta"),
                      (_saml, "SAML metadata"),
                      (_scim, "SCIM"),
                      (_mcp, "MCP/shadow-MCP")):
        try:
            fn(ctx)
        except Exception as e:
            ctx.log("WARN", "interface_probe", f"{label} probe error: {e}")
    ctx.log("OK", "interface_probe",
            "interface/identity discovery complete (gRPC, Socket.IO, AsyncAPI, "
            "JSON:API, SAML, SCIM, MCP)")
