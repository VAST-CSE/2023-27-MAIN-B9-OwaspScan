"""
Lightweight dynamic scanner: sends real HTTP(S) requests at a target and flags
likely OWASP Top 10 issues from the responses. Everything here is read-only /
non-destructive (GETs, no auth brute-forcing, no payload loops) and rate-limited.

LEGAL: only point this at hosts you own or are explicitly authorised to test.
Active scanning of systems you don't control can be illegal even when the
requests themselves are harmless.
"""
import http.client
import re
import ssl
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import Finding, Severity

USER_AGENT = "owaspscan/0.2 (+authorized-security-testing)"

SECURITY_HEADERS = {
    "content-security-policy": ("CSP", Severity.MEDIUM),
    "strict-transport-security": ("HSTS", Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW),
    "x-frame-options": ("X-Frame-Options / frame-ancestors", Severity.MEDIUM),
    "referrer-policy": ("Referrer-Policy", Severity.LOW),
}

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local",
    "/.svn/entries", "/.DS_Store", "/.aws/credentials",
    "/server-status", "/phpinfo.php", "/config.php.bak",
    "/wp-config.php.bak", "/backup.zip", "/.htpasswd",
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?_", r"valid MySQL result",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"SQLite3?::", r"SQLite/JDBCDriver",
    r"System\.Data\.SQLite\.SQLiteException", r"Unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for ODBC Drivers", r"ORA-\d{5}",
]
_SQL_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

WEAK_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
MAX_BODY = 300_000
MAX_REDIRECTS = 6


class FetchError(Exception):
    pass


def _fetch_once(url: str, timeout: float, method: str = "GET") -> dict:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise FetchError(f"Not a usable http(s) URL: {url}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    cert_info: Optional[dict] = None
    tls_version = None
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        try:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            conn.connect()
            cert = conn.sock.getpeercert()
            tls_version = conn.sock.version()
            not_after = cert.get("notAfter") if cert else None
            expired = False
            if not_after:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                expired = exp < datetime.now(timezone.utc)
            cert_info = {"verified": True, "expired": expired}
        except ssl.SSLCertVerificationError as e:
            cert_info = {"verified": False, "error": str(e)}
            ctx2 = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx2)
            conn.connect()
            tls_version = conn.sock.version()
        except (OSError, TimeoutError) as e:
            raise FetchError(str(e))
    else:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        except OSError as e:
            raise FetchError(str(e))

    try:
        conn.request(method, path, headers={"User-Agent": USER_AGENT, "Host": host, "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(MAX_BODY)
    except (OSError, TimeoutError, http.client.HTTPException) as e:
        raise FetchError(str(e))
    finally:
        conn.close()

    return {
        "status": resp.status,
        "headers": resp.getheaders(),  # list of (name, value), preserves repeated Set-Cookie
        "body": body.decode("utf-8", "replace"),
        "location": resp.getheader("Location"),
        "cert_info": cert_info,
        "tls_version": tls_version,
        "scheme": parsed.scheme,
        "host": host,
        "url": url,
    }


def fetch(url: str, timeout: float = 8.0) -> dict:
    """Follow redirects manually so we can see the whole chain (e.g. http->https)."""
    seen, current = [], url
    for _ in range(MAX_REDIRECTS):
        resp = _fetch_once(current, timeout)
        seen.append(resp)
        if resp["status"] in (301, 302, 303, 307, 308) and resp["location"]:
            current = urllib.parse.urljoin(current, resp["location"])
            continue
        break
    resp["chain"] = seen
    return resp


def _header_map(headers) -> Dict[str, str]:
    return {k.lower(): v for k, v in headers}


def _finding(rid, owasp, sev, title, url, snippet, fix) -> Finding:
    return Finding(rid, owasp, sev, title, url, 0, snippet[:160], fix)


def check_security_headers(resp: dict) -> List[Finding]:
    hm = _header_map(resp["headers"])
    out = []
    for key, (label, sev) in SECURITY_HEADERS.items():
        if key not in hm:
            out.append(_finding("OWS-WEB-A05-001", "A05", sev, f"Missing security header: {label}",
                                 resp["url"], f"response had no {label} header", f"Add a {label} header."))
    server = hm.get("server") or hm.get("x-powered-by")
    if server and any(c.isdigit() for c in server):
        out.append(_finding("OWS-WEB-A05-002", "A05", Severity.LOW, "Server/framework version disclosed in headers",
                             resp["url"], f"{('Server' if 'server' in hm else 'X-Powered-By')}: {server}",
                             "Suppress or generalise version-revealing banners."))
    return out


def check_cookies(resp: dict) -> List[Finding]:
    out = []
    for name, value in resp["headers"]:
        if name.lower() != "set-cookie":
            continue
        low = value.lower()
        cookie_name = value.split("=", 1)[0].strip()
        if "httponly" not in low:
            out.append(_finding("OWS-WEB-A07-001", "A07", Severity.MEDIUM,
                                 f"Cookie '{cookie_name}' missing HttpOnly",
                                 resp["url"], value[:120], "Set HttpOnly on session/auth cookies."))
        if resp["scheme"] == "https" and "secure" not in low:
            out.append(_finding("OWS-WEB-A07-002", "A07", Severity.MEDIUM,
                                 f"Cookie '{cookie_name}' missing Secure flag",
                                 resp["url"], value[:120], "Set Secure on cookies served over HTTPS."))
        if "samesite" not in low:
            out.append(_finding("OWS-WEB-A07-003", "A07", Severity.LOW,
                                 f"Cookie '{cookie_name}' missing SameSite",
                                 resp["url"], value[:120], "Set SameSite=Lax or Strict."))
    return out


def check_transport(url: str, resp: dict) -> List[Finding]:
    out = []
    chain = resp["chain"]
    first = chain[0]
    if first["scheme"] == "http":
        upgraded = any(r["scheme"] == "https" for r in chain[1:])
        if not upgraded:
            out.append(_finding("OWS-WEB-A02-001", "A02", Severity.HIGH,
                                 "Site served over plain HTTP with no redirect to HTTPS",
                                 url, f"GET {url} -> {first['status']}, stayed on http",
                                 "Redirect all HTTP traffic to HTTPS and send HSTS."))
    for r in chain:
        if r["scheme"] != "https":
            continue
        ci = r["cert_info"] or {}
        if ci.get("verified") is False:
            out.append(_finding("OWS-WEB-A02-002", "A02", Severity.HIGH,
                                 "TLS certificate failed verification", r["url"],
                                 ci.get("error", ""), "Install a valid certificate from a trusted CA."))
        elif ci.get("expired"):
            out.append(_finding("OWS-WEB-A02-003", "A02", Severity.HIGH,
                                 "TLS certificate is expired", r["url"], "",
                                 "Renew the certificate."))
        if r.get("tls_version") in WEAK_TLS:
            out.append(_finding("OWS-WEB-A02-004", "A02", Severity.HIGH,
                                 f"Weak TLS protocol negotiated ({r['tls_version']})", r["url"], "",
                                 "Disable TLS 1.1/1.0/SSLv3; require TLS 1.2+."))
    return out


def check_sensitive_paths(base_url: str, timeout: float, delay: float) -> List[Finding]:
    out = []
    parsed = urllib.parse.urlsplit(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    nonce = uuid.uuid4().hex[:10]
    try:
        baseline = _fetch_once(f"{root}/__owaspscan_nonexistent_{nonce}__", timeout)
    except FetchError:
        baseline = None
    time.sleep(delay)
    for path in SENSITIVE_PATHS:
        try:
            r = _fetch_once(root + path, timeout)
        except FetchError:
            continue
        finally:
            time.sleep(delay)
        soft_404 = baseline is not None and r["status"] == baseline["status"] and \
            len(r["body"]) and abs(len(r["body"]) - len(baseline["body"])) < 20
        if r["status"] == 200 and r["body"].strip() and not soft_404:
            out.append(_finding("OWS-WEB-A01-001", "A01", Severity.HIGH,
                                 f"Sensitive path publicly accessible: {path}",
                                 root + path, f"HTTP {r['status']}, {len(r['body'])} bytes",
                                 "Remove the file from the web root or block it at the server/proxy."))
    return out


def check_reflected_params(url: str, timeout: float, delay: float) -> List[Finding]:
    out = []
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return out
    for name, _ in params[:5]:
        token = "owc" + uuid.uuid4().hex[:6]
        for payload, rid, sev, title, fix, is_sqli in (
            (f"{token}<owscan>", "OWS-WEB-A03-001", Severity.HIGH,
             "User input reflected unescaped in response (possible XSS)",
             "HTML-encode output and set a Content-Security-Policy.", False),
            (f"{token}'", "OWS-WEB-A03-002", Severity.CRITICAL,
             "Database error message triggered by single-quote input (possible SQL injection)",
             "Use parameterised queries; never build SQL from request input.", True),
        ):
            new_params = [(n, payload if n == name else v) for n, v in params]
            test_url = urllib.parse.urlunsplit((
                parsed.scheme, parsed.netloc, parsed.path,
                urllib.parse.urlencode(new_params), ""))
            try:
                r = _fetch_once(test_url, timeout)
            except FetchError:
                continue
            finally:
                time.sleep(delay)
            if is_sqli:
                if _SQL_RE.search(r["body"]):
                    out.append(_finding(rid, "A03", sev, title, test_url,
                                         f"param '{name}' triggered a DB error pattern", fix))
            else:
                if f"{token}<owscan>" in r["body"]:
                    out.append(_finding(rid, "A03", sev, title, test_url,
                                         f"param '{name}' reflected verbatim, unescaped", fix))
    return out


def scan_url(url: str, timeout: float = 8.0, delay: float = 0.25,
             path_probe: bool = True, param_probe: bool = True) -> List[Finding]:
    if "://" not in url:
        url = "https://" + url
    findings: List[Finding] = []
    try:
        resp = fetch(url, timeout)
    except FetchError as e:
        return [_finding("OWS-WEB-ERR", "A05", Severity.LOW, "Target unreachable", url, str(e),
                          "Verify the URL, network access, and that the host is up.")]

    findings += check_security_headers(resp)
    findings += check_cookies(resp)
    findings += check_transport(url, resp)
    time.sleep(delay)
    if path_probe:
        findings += check_sensitive_paths(url, timeout, delay)
    if param_probe:
        findings += check_reflected_params(url, timeout, delay)

    uniq = {(f.rule_id, f.path): f for f in findings}
    return sorted(uniq.values(), key=lambda f: -f.severity)


def scan_urls(urls, **kwargs) -> List[Finding]:
    out: List[Finding] = []
    for u in urls:
        out += scan_url(u, **kwargs)
    return out
