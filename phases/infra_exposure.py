"""
Phase: infra_exposure

Catches misconfigurations that leak internal infrastructure data — a category
nuclei templates often miss because the responses are very environment-specific.

Targets:
  1. Spring Boot Actuator endpoints (heapdump, env, beans, mappings, threaddump)
     → CRITICAL: heap dump can contain JWT/session/passwords; env can have DB URLs
  2. Docker Registry v2 API exposed (/v2/_catalog)
     → CRITICAL: image enumeration + pull access without auth
  3. Kubernetes API server exposed (/api/v1/namespaces)
     → CRITICAL: cluster control plane reachable
  4. Prometheus / metrics endpoints (/metrics)
     → MEDIUM: internal hostnames, version disclosure, queue sizes
  5. Sentry DSN leaked in JS (https://KEY@org.ingest.sentry.io/PROJECT)
     → HIGH: attacker can send arbitrary events, consume quota, or extract
       project ID for further enumeration
  6. Hashicorp Vault unsealed (/v1/sys/health)
     → CRITICAL: sealed=false means attacker can read secrets
  7. etcd API (/v2/keys, /version)
     → CRITICAL: full database of secrets
  8. Consul agent (/v1/agent/self)
     → HIGH: service catalog disclosure
  9. Elasticsearch (/_cat/indices, /_cluster/health)
     → HIGH/CRITICAL: data exfil + cluster admin

All probes are READ-ONLY GETs. No writes, no destructive operations.
"""
from __future__ import annotations
import json
import re
from urllib.parse import urljoin, urlparse

from core import anti_block, noise_filter
from core.targets import get_root_domains

try:
    import requests
except ImportError:
    requests = None


# Each: (path, check_id, severity-on-200, description)
INFRA_CHECKS = [
    # Spring Boot Actuator (v1 + v2)
    ("/actuator",            "spring_actuator_root",    "MEDIUM",
     "Spring Boot actuator base path reachable"),
    ("/actuator/env",        "spring_env",              "CRITICAL",
     "Spring Boot /actuator/env leaks environment variables (DB URLs, secrets)"),
    ("/actuator/heapdump",   "spring_heapdump",         "CRITICAL",
     "Spring Boot heapdump downloadable — JVM memory dump includes sessions/JWTs"),
    ("/actuator/beans",      "spring_beans",            "MEDIUM",
     "Spring Boot bean tree exposed — internal class structure"),
    ("/actuator/mappings",   "spring_mappings",         "MEDIUM",
     "Spring Boot mappings expose all HTTP routes (incl. admin/internal)"),
    ("/actuator/threaddump", "spring_threaddump",       "HIGH",
     "Spring Boot thread dump can contain stack traces with secrets"),
    ("/actuator/conftree",   "spring_conftree",         "HIGH",
     "Spring Boot config tree exposes property sources"),
    ("/actuator/configprops", "spring_configprops",     "HIGH",
     "Spring Boot config properties exposed"),
    ("/actuator/loggers",    "spring_loggers",          "MEDIUM",
     "Spring Boot loggers actuator — log-level tampering risk"),
    ("/actuator/jolokia",    "spring_jolokia",          "CRITICAL",
     "Jolokia mgmt endpoint — JMX RCE risk (CVE-2022-22965 vicinity)"),
    # Old-style (v1.x without /actuator prefix)
    ("/env",                 "spring_env_legacy",       "CRITICAL",
     "Legacy Spring /env endpoint — environment variables leak"),
    ("/heapdump",            "spring_heapdump_legacy",  "CRITICAL",
     "Legacy Spring /heapdump — JVM memory snapshot"),
    ("/trace",               "spring_trace_legacy",     "HIGH",
     "Legacy Spring /trace — last HTTP requests with headers/cookies"),
    ("/dump",                "spring_dump_legacy",      "HIGH",
     "Legacy Spring /dump — thread dump"),
    # Docker Registry v2
    ("/v2/",                 "docker_registry_root",    "MEDIUM",
     "Docker Registry v2 API root reachable"),
    ("/v2/_catalog",         "docker_registry_catalog", "CRITICAL",
     "Docker Registry catalog — full image list without auth"),
    # Kubernetes
    ("/api/v1/namespaces",   "k8s_api",                 "CRITICAL",
     "Kubernetes API exposed — list namespaces"),
    ("/api/v1/pods",         "k8s_pods",                "CRITICAL",
     "Kubernetes pods listable"),
    ("/healthz",             "k8s_healthz",             "LOW",
     "Kubernetes health endpoint"),
    ("/metrics",             "prometheus_metrics",      "MEDIUM",
     "Prometheus /metrics endpoint exposed"),
    # Hashicorp
    ("/v1/sys/health",       "vault_health",            "HIGH",
     "Hashicorp Vault sys/health endpoint"),
    ("/v1/sys/seal-status",  "vault_seal_status",       "HIGH",
     "Hashicorp Vault seal-status — verify if unsealed"),
    # etcd
    ("/v2/keys/",            "etcd_v2_keys",            "CRITICAL",
     "etcd v2 keys API — secrets DB"),
    ("/v3/kv/range",         "etcd_v3_kv",              "CRITICAL",
     "etcd v3 KV range API"),
    ("/version",             "etcd_or_consul_version",  "LOW",
     "Version endpoint (etcd/consul/many) — informational"),
    # Consul
    ("/v1/agent/self",       "consul_agent",            "HIGH",
     "Consul agent self endpoint — full agent config"),
    ("/v1/catalog/services", "consul_services",         "HIGH",
     "Consul service catalog"),
    # Elasticsearch / OpenSearch
    ("/_cat/indices?v",      "elastic_indices",         "HIGH",
     "Elasticsearch indices listing"),
    ("/_cluster/health",     "elastic_cluster_health",  "MEDIUM",
     "Elasticsearch cluster health"),
    ("/_cluster/state",      "elastic_cluster_state",   "CRITICAL",
     "Elasticsearch cluster state — full topology"),
    ("/_nodes",              "elastic_nodes",           "HIGH",
     "Elasticsearch nodes info"),
    ("/_search?size=1",      "elastic_search",          "CRITICAL",
     "Elasticsearch search API open — data exfil"),
    # RabbitMQ management
    ("/api/overview",        "rabbitmq_overview",       "HIGH",
     "RabbitMQ management API overview"),
    # Kibana
    ("/app/kibana",          "kibana_app",              "HIGH",
     "Kibana UI reachable"),
    ("/api/status",          "kibana_status",           "MEDIUM",
     "Kibana status API"),
    # Grafana
    ("/api/datasources",     "grafana_datasources",     "CRITICAL",
     "Grafana datasources API — DB credentials"),
    ("/api/admin/users",     "grafana_admin_users",     "CRITICAL",
     "Grafana admin users API"),
    ("/login",               "grafana_login",           "INFO",
     "Login page — informational only (fingerprint)"),
    # Jenkins
    ("/script",              "jenkins_script",          "CRITICAL",
     "Jenkins script console — RCE if reachable"),
    ("/asynchPeople/",       "jenkins_people",          "MEDIUM",
     "Jenkins user enumeration"),
    ("/manage",              "jenkins_manage",          "HIGH",
     "Jenkins manage panel"),
    # Apache Spark / Hadoop / Kafka
    ("/jmx",                 "spark_jmx",               "HIGH",
     "Apache Spark/Hadoop JMX endpoint"),
    # GraphQL introspection (often forgotten)
    ("/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D",
                             "graphql_introspection",    "MEDIUM",
     "GraphQL introspection enabled (often left on in prod)"),
]


# Patterns that confirm we got real content (not a 200 landing page)
CONFIRM_PATTERNS = {
    "spring_actuator_root":  re.compile(r"\"_links\"|\"actuator\"", re.I),
    "spring_env":            re.compile(r"\"propertySources\"|\"activeProfiles\"", re.I),
    "spring_heapdump":       re.compile(rb"JAVA PROFILE|HPROF", re.I),
    "spring_beans":          re.compile(r"\"beans\"\s*:|\"context\"\s*:", re.I),
    "spring_mappings":       re.compile(r"\"dispatcherServlets\"|\"servletMappings\"", re.I),
    "spring_threaddump":     re.compile(r"\"threadName\"|\"threadId\"|java\.lang", re.I),
    "spring_jolokia":        re.compile(r"\"agent\":\"jolokia\"|jolokia", re.I),
    "spring_env_legacy":     re.compile(r"\"systemProperties\"|\"server\.port\"", re.I),
    "spring_trace_legacy":   re.compile(r"\"path\"\s*:\s*\"/", re.I),
    "docker_registry_root":  re.compile(r"Docker-Distribution|\"errors\".*UNAUTHORIZED|^\{\}\s*$", re.I),
    "docker_registry_catalog": re.compile(r"\"repositories\"\s*:\s*\[", re.I),
    "k8s_api":               re.compile(r"\"kind\"\s*:\s*\"NamespaceList\"", re.I),
    "k8s_pods":              re.compile(r"\"kind\"\s*:\s*\"PodList\"", re.I),
    "prometheus_metrics":    re.compile(r"^# HELP |^# TYPE ", re.M),
    "vault_health":          re.compile(r"\"sealed\"|\"initialized\"", re.I),
    "vault_seal_status":     re.compile(r"\"sealed\"\s*:", re.I),
    "etcd_v2_keys":          re.compile(r"\"action\"\s*:|\"node\"\s*:", re.I),
    "etcd_v3_kv":            re.compile(r"\"header\"\s*:|\"kvs\"\s*:", re.I),
    "consul_agent":          re.compile(r"\"Config\"\s*:|\"Member\"\s*:", re.I),
    "consul_services":       re.compile(r"\"consul\"\s*:|\"ServiceID\"", re.I),
    "elastic_indices":       re.compile(r"^(health|yellow|green|red)\s+|index\s+", re.I | re.M),
    "elastic_cluster_health":re.compile(r"\"cluster_name\"|\"status\"", re.I),
    "elastic_cluster_state": re.compile(r"\"cluster_uuid\"|\"master_node\"", re.I),
    "elastic_nodes":         re.compile(r"\"nodes\"\s*:|\"_nodes\"", re.I),
    "elastic_search":        re.compile(r"\"hits\"\s*:|\"took\"\s*:", re.I),
    "rabbitmq_overview":     re.compile(r"rabbitmq_version|\"node\"\s*:\s*\"rabbit@", re.I),
    "kibana_app":            re.compile(r"kbn-name|window\.kbn|kibanaBaseUrl", re.I),
    "grafana_datasources":   re.compile(r"\"datasource\"|\"type\"\s*:\s*\"(prometheus|mysql|postgres)\"", re.I),
    "grafana_admin_users":   re.compile(r"\"login\"|\"email\"|\"isAdmin\"", re.I),
    "jenkins_script":        re.compile(r"jenkins|Script Console", re.I),
    "graphql_introspection": re.compile(r"\"__schema\"|\"types\"\s*:\s*\[", re.I),
}


# Sentry DSN regex — match the URL form sentry uses
SENTRY_DSN_RE = re.compile(
    r"https://[0-9a-f]{16,32}@(?:[a-z0-9\-]+\.)?ingest(?:\.[a-z]+)?\.sentry\.io/\d+",
    re.I,
)


def run(ctx):
    if not requests:
        return

    # Build target hosts list: alive.txt + targets themselves
    targets = set()
    alive_file = ctx.output / "recon" / "alive.txt"
    if alive_file.exists():
        for url in ctx.runner.read_lines(alive_file):
            targets.add(url)
    for d in get_root_domains(ctx):
        targets.add(f"https://{d}")
        targets.add(f"http://{d}")

    in_scope = set(get_root_domains(ctx))
    targets = [t for t in targets
               if not noise_filter.is_noise(t, in_scope_hosts=in_scope)[0]]

    if not targets:
        ctx.log("INFO", "infra_exposure", "no targets — skipping")
        return

    ctx.log("INFO", "infra_exposure",
            f"━━━ Infra exposure: {len(INFRA_CHECKS)} checks × "
            f"{min(len(targets), 50)} hosts ━━━")

    n = 0
    for base in sorted(set(targets))[:50]:
        n += _scan_host(ctx, base.rstrip("/"))

    # Part 2: scan all collected JS files for Sentry DSN leaks
    n += _scan_sentry_dsn(ctx, in_scope)

    ctx.log("OK", "infra_exposure", f"infra_exposure: {n} findings")


def _scan_host(ctx, base: str) -> int:
    host = urlparse(base).hostname or base
    found = 0
    # Skip if base failed early (avoid hammering dead hosts)
    consecutive_errors = 0

    for path, check_id, severity, description in INFRA_CHECKS:
        if consecutive_errors >= 5:
            return found
        url = base + path
        try:
            headers = anti_block.headers_for(host)
            # Allow a bigger body for heapdumps but cap at 10MB head
            r = requests.get(url, headers=headers, timeout=12, verify=False,
                             allow_redirects=False, cookies={}, stream=True)
            # Read at most 200KB (enough for pattern match; saves bandwidth)
            content = r.raw.read(200_000, decode_content=True) or b""
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                text = ""
            anti_block.observe(host, r.status_code, len(content), text[:1000])
        except Exception:
            consecutive_errors += 1
            continue

        if r.status_code not in (200, 401):
            consecutive_errors += 1 if r.status_code in (502, 503, 504) else 0
            continue

        consecutive_errors = 0

        # 401 alone means the endpoint *exists* — flag it as INFO (fingerprint)
        if r.status_code == 401:
            # Don't flood with 401 findings; only flag interesting ones
            if check_id in ("docker_registry_root", "k8s_api", "vault_health",
                            "grafana_admin_users", "etcd_v2_keys"):
                ctx.save_finding({
                    "phase": "infra_exposure", "severity": "INFO", "confidence": "HIGH",
                    "title": f"{check_id} present but requires auth (fingerprint)",
                    "target": host, "url": url, "method": "GET",
                    "evidence": f"GET {url} → 401. Service is deployed; check for "
                                "auth bypass / default creds.",
                    "description": description,
                    "impact": "Information disclosure: confirms service is running here.",
                    "remediation": "Ensure auth is enforced (already partially is). "
                                   "Restrict the endpoint to internal IPs at WAF/LB level.",
                    "cwe": "CWE-200", "mrs_score": 35,
                })
                found += 1
            continue

        # 200 — confirm content matches expected pattern (avoids generic 200s)
        confirm = CONFIRM_PATTERNS.get(check_id)
        confirmed = True
        if confirm is not None:
            if isinstance(confirm.pattern, bytes):
                confirmed = bool(confirm.search(content))
            else:
                confirmed = bool(confirm.search(text))
        else:
            # v2.20: no confirmation pattern for this check. Fail CLOSED for
            # CRITICAL/HIGH — a 200 alone must not raise a severe finding (this is
            # what produced the /heapdump SPA false positives). Also drop if the
            # body looks like an HTML app-shell / SPA rather than the service.
            if severity in ("CRITICAL", "HIGH"):
                confirmed = False
        # Any check: if the body is an HTML page, it's a landing/SPA page, not
        # a heapdump/actuator/registry payload — reject.
        if confirmed and check_id.startswith(("spring_", "docker_", "k8s_", "etcd_", "es_")):
            if "<html" in text[:500].lower() or "<!doctype html" in text[:500].lower():
                confirmed = False
        if not confirmed:
            continue

        ctx.save_finding({
            "phase": "infra_exposure", "severity": severity, "confidence": "HIGH",
            "title": f"{check_id}: {description}",
            "target": host, "url": url, "method": "GET",
            "evidence": f"GET {url} → 200, response confirms service. "
                        f"Sample (first 300 chars): {text[:300]!r}",
            "description": description + ". This endpoint is reachable without "
                          "authentication; the response confirms the service type.",
            "impact": _impact_for(check_id),
            "remediation": _remediation_for(check_id),
            "cwe": _cwe_for(check_id),
            "mrs_score": _mrs_for(severity),
        })
        found += 1
    return found


def _scan_sentry_dsn(ctx, in_scope) -> int:
    """Scan collected JS for Sentry DSN URLs."""
    js_file = ctx.output / "recon" / "javascript.txt"
    if not js_file.exists():
        return 0
    n = 0
    seen_dsns = set()
    for js_url in ctx.runner.read_lines(js_file)[:50]:
        if noise_filter.is_noise(js_url, in_scope_hosts=in_scope)[0]:
            continue
        host = urlparse(js_url).hostname or ""
        try:
            r = requests.get(js_url, headers=anti_block.headers_for(host),
                             timeout=10, verify=False)
            anti_block.observe(host, r.status_code, len(r.content))
            if r.status_code != 200:
                continue
            text = r.text[:2_000_000]
        except Exception:
            continue

        for m in SENTRY_DSN_RE.finditer(text):
            dsn = m.group(0)
            if dsn in seen_dsns:
                continue
            seen_dsns.add(dsn)
            # Extract project ID
            proj_match = re.search(r"sentry\.io/(\d+)", dsn)
            project_id = proj_match.group(1) if proj_match else "?"
            ctx.save_finding({
                "phase": "infra_exposure", "severity": "HIGH", "confidence": "HIGH",
                "title": "Sentry DSN exposed in public JavaScript",
                "target": host, "url": js_url,
                "evidence": f"Sentry DSN found in {js_url}: project_id={project_id}. "
                            f"DSN (partial): {dsn[:30]}...@...sentry.io/{project_id}",
                "description": "A Sentry DSN was found embedded in a public JS bundle. "
                              "Sentry DSNs technically grant 'event ingest' permission. "
                              "An attacker can: (1) send arbitrary fake events to consume "
                              "the customer's event quota / cause billing pain; (2) flood "
                              "alerts and obscure real incidents; (3) potentially leak "
                              "internal project ID for OSINT.",
                "impact": "Quota exhaustion + alert flooding + project ID disclosure.",
                "remediation": "Sentry treats DSNs as semi-public, but it's still good "
                              "hygiene to use a per-environment DSN that's rate-limited, "
                              "and to set up inbound filters for spam events.",
                "cwe": "CWE-200", "mrs_score": 60,
                "payload": dsn,
            })
            n += 1
    return n


def _impact_for(check_id: str) -> str:
    crit = {
        "spring_env":          "Database URLs, secrets, JWT keys, profile names leaked.",
        "spring_env_legacy":   "Database URLs, secrets, JWT keys leaked.",
        "spring_heapdump":     "JVM memory dump downloadable — extract session cookies, "
                                "JWTs, passwords. Use 'eclipse MAT' to analyze.",
        "spring_heapdump_legacy": "Same as above — JVM dump downloadable.",
        "spring_jolokia":      "JMX management interface reachable — potential RCE.",
        "docker_registry_catalog": "All Docker image names enumerable; depending on auth "
                                    "config, images may be pullable too.",
        "k8s_api":             "Kubernetes control plane exposed — namespaces/pods/services "
                                "enumerable. Cluster takeover risk.",
        "k8s_pods":            "Pod listing → cluster topology mapping → targeted exploits.",
        "vault_health":        "Vault status disclosed — combine with seal-status to know if "
                                "secret DB is unsealed and reachable.",
        "etcd_v2_keys":        "etcd is the secret store. Full read access = full secret DB.",
        "etcd_v3_kv":          "Same as above (v3 protocol).",
        "elastic_cluster_state":"Full ES cluster topology + index names + mapping types.",
        "elastic_search":      "Open _search means data exfiltration without auth.",
        "grafana_datasources": "Datasource credentials (DB passwords) leak in some Grafana versions.",
        "grafana_admin_users": "User list with emails + admin status.",
        "jenkins_script":      "Jenkins script console = remote code execution.",
    }
    return crit.get(check_id,
                    "Misconfiguration: internal management endpoint reachable from internet.")


def _remediation_for(check_id: str) -> str:
    if check_id.startswith("spring_"):
        return ("Set management.endpoints.web.exposure.include=health,info only "
                "(NOT '*'). Bind actuator to a separate management port and "
                "restrict it to internal IPs.")
    if check_id.startswith("docker_"):
        return ("Enable Docker registry token authentication (REGISTRY_AUTH=htpasswd). "
                "Never expose /v2/_catalog without auth.")
    if check_id.startswith("k8s_"):
        return ("Restrict API server to bastion / VPN. Never expose port 6443 / 8001 to "
                "the public internet.")
    if check_id.startswith("vault_") or check_id.startswith("etcd_") or check_id.startswith("consul_"):
        return ("Bind to localhost / private network only. Use mTLS for API access.")
    if check_id.startswith("elastic_"):
        return ("Enable X-Pack security or Open Distro security. Bind to private network. "
                "Use API keys for any external integrations.")
    if check_id == "grafana_admin_users" or check_id == "grafana_datasources":
        return ("Enforce login in grafana.ini ([auth.anonymous] enabled=false). "
                "Use a reverse proxy with auth in front of Grafana.")
    if check_id == "jenkins_script":
        return ("Lock down Jenkins with role-based auth. The script console grants RCE; "
                "restrict to admin role only.")
    return "Restrict access to internal networks; require authentication."


def _cwe_for(check_id: str) -> str:
    if check_id in ("spring_jolokia", "jenkins_script"):
        return "CWE-78"   # OS command injection / RCE
    if "heapdump" in check_id or "env" in check_id:
        return "CWE-200"  # info disclosure
    return "CWE-1188"     # insecure default permission


def _mrs_for(sev: str) -> int:
    return {"CRITICAL": 92, "HIGH": 80, "MEDIUM": 60, "LOW": 40, "INFO": 30}.get(sev, 30)
