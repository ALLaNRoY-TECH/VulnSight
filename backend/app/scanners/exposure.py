"""Web misconfiguration checks: redirects, cookies, CORS, exposed files."""
from __future__ import annotations

import asyncio
import re
from http.cookies import SimpleCookie
from typing import Any, Callable

import httpx

from ..models import Finding, finding
from .http import fetch
from .target import Target, TargetError

M = "exposure"
EVIL_ORIGIN = "https://evil-vulnsight.example"
MAX_BODY = 64 * 1024


async def _snippet(client: httpx.AsyncClient, url: str) -> tuple[int, bytes, str]:
    async with client.stream("GET", url, follow_redirects=False) as r:
        buf = b""
        async for chunk in r.aiter_bytes():
            buf += chunk
            if len(buf) >= MAX_BODY:
                break
        return r.status_code, buf[:MAX_BODY], r.headers.get("content-type", "")


def _text(b: bytes) -> str:
    return b.decode("utf-8", "replace")


def _not_html(ct: str, body: bytes) -> bool:
    return "html" not in ct.lower() and b"<html" not in body[:500].lower()


# path, title, severity, validator(status, body, content_type), remediation
SENSITIVE: list[tuple[str, str, str, Callable[[int, bytes, str], bool], str]] = [
    ("/.git/HEAD", "Git repository exposed", "critical",
     lambda s, b, c: s == 200 and _text(b).lstrip().startswith("ref:"),
     "Block access to /.git (e.g. nginx `location ~ /\\.git { deny all; }`) and never deploy the .git folder."),
    ("/.env", "Environment file (.env) exposed", "critical",
     lambda s, b, c: s == 200 and _not_html(c, b) and bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", b)),
     "Remove .env from the web root, block dotfiles, and rotate every secret it contained."),
    ("/backup.sql", "Database dump exposed", "critical",
     lambda s, b, c: s == 200 and bool(re.search(rb"CREATE TABLE|INSERT INTO", b, re.I)),
     "Delete backups from the web root and store them in private, encrypted storage."),
    ("/wp-config.php.bak", "WordPress config backup exposed", "critical",
     lambda s, b, c: s == 200 and b"DB_PASSWORD" in b,
     "Delete the backup file and rotate the database credentials."),
    ("/.htpasswd", ".htpasswd file exposed", "high",
     lambda s, b, c: s == 200 and _not_html(c, b) and bool(re.search(rb"(?m)^[\w.-]+:\$?[\w./$]{10,}", b)),
     "Move password files outside the web root and deny access to dotfiles."),
    ("/actuator/env", "Spring Boot actuator exposed", "high",
     lambda s, b, c: s == 200 and b"propertySources" in b,
     "Disable or authenticate actuator endpoints (management.endpoints.web.exposure.include)."),
    ("/server-status", "Apache server-status exposed", "medium",
     lambda s, b, c: s == 200 and b"Apache Server Status" in b,
     "Restrict mod_status to localhost / admin IPs."),
    ("/phpinfo.php", "phpinfo() page exposed", "medium",
     lambda s, b, c: s == 200 and (b"phpinfo()" in b or b"PHP Version" in b),
     "Remove phpinfo.php from production."),
    ("/.DS_Store", ".DS_Store file exposed", "low",
     lambda s, b, c: s == 200 and b[4:8] == b"Bud1",
     "Delete .DS_Store files and add them to your deploy ignore list."),
]


async def _check_redirect(client: httpx.AsyncClient, target: Target, https_ok: bool) -> list[Finding]:
    if not https_ok:
        return []
    try:
        r = await fetch(client, target.http_url)
    except (ConnectionError, TargetError) as exc:
        return [finding("http-redirect", M, "Plain HTTP not served", "pass",
                        evidence=f"Port 80 not reachable ({str(exc)[:80]})")]
    chain = " → ".join([str(h.url) for h in r.history] + [str(r.url)])
    if r.url.scheme == "https":
        return [finding("http-redirect", M, "HTTP redirects to HTTPS", "pass", evidence=chain)]
    return [finding(
        "http-no-redirect", M, "HTTP does not redirect to HTTPS", "fail", "medium",
        "Visitors who type the bare domain stay on an unencrypted connection.",
        evidence=chain,
        remediation="Return a 301 redirect from every http:// URL to its https:// equivalent and enable HSTS.")]


def _check_cookies(resp: httpx.Response) -> list[Finding]:
    raw = []
    for r in list(resp.history) + [resp]:
        raw += r.headers.get_list("set-cookie")
    if not raw:
        return [finding("cookies-none", M, "No cookies set on landing page", "info", "info")]
    problems = []
    for header in raw:
        jar = SimpleCookie()
        try:
            jar.load(header)
        except Exception:
            continue
        low = header.lower()
        for name in jar:
            missing = []
            if "secure" not in low:
                missing.append("Secure")
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                problems.append(f"{name}: missing {', '.join(missing)}")
    if not problems:
        return [finding("cookies-ok", M, f"All {len(raw)} cookie(s) use secure flags", "pass")]
    sev = "medium" if any("Secure" in p or "HttpOnly" in p for p in problems) else "low"
    return [finding(
        "cookie-flags", M, f"{len(problems)} cookie(s) missing security flags", "fail", sev,
        "Cookies without Secure can leak over HTTP, without HttpOnly can be stolen via XSS, and without "
        "SameSite are exposed to CSRF.",
        evidence="\n".join(problems[:15]),
        remediation="Set cookies with `Secure; HttpOnly; SameSite=Lax` (or Strict). Only omit HttpOnly "
                    "for cookies JavaScript genuinely needs.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"])]


async def _check_cors(client: httpx.AsyncClient, url: str) -> list[Finding]:
    try:
        r = await fetch(client, url, headers={"Origin": EVIL_ORIGIN})
    except (ConnectionError, TargetError):
        return []
    acao = r.headers.get("access-control-allow-origin")
    acac = (r.headers.get("access-control-allow-credentials") or "").lower() == "true"
    if acao == EVIL_ORIGIN and acac:
        return [finding("cors-reflect-creds", M, "CORS reflects any origin with credentials", "fail", "high",
                        "Any website can read authenticated responses from this site on behalf of a logged-in user.",
                        evidence=f"Origin: {EVIL_ORIGIN}\nAccess-Control-Allow-Origin: {acao}\n"
                                 "Access-Control-Allow-Credentials: true",
                        remediation="Validate the Origin against an explicit allow-list; never reflect it blindly "
                                    "when credentials are allowed.",
                        references=["https://portswigger.net/web-security/cors"])]
    if acao == EVIL_ORIGIN:
        return [finding("cors-reflect", M, "CORS reflects arbitrary origins", "warn", "medium",
                        "The server echoes back any Origin, letting any site read its responses.",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation="Use an explicit allow-list of trusted origins.",
                        references=["https://portswigger.net/web-security/cors"])]
    if acao == "*":
        return [finding("cors-wildcard", M, "CORS allows any origin (*)", "info", "info",
                        "Fine for public, unauthenticated data; make sure no private data is served here.",
                        evidence="Access-Control-Allow-Origin: *")]
    return [finding("cors-ok", M, "CORS does not trust arbitrary origins", "pass")]


async def _check_files(client: httpx.AsyncClient, base: str) -> tuple[list[Finding], list[dict]]:
    sem = asyncio.Semaphore(6)

    async def probe(item):
        path, title, sev, ok, fix = item
        async with sem:
            try:
                status, body, ct = await _snippet(client, base + path)
            except Exception:
                return None
            if ok(status, body, ct):
                return finding(f"exposed{path.replace('/', '-').replace('.', '')}", M, title, "fail", sev,
                               f"{path} is publicly downloadable and contains sensitive content.",
                               evidence=f"GET {path} → {status}\n{_text(body[:200])}",
                               remediation=fix,
                               references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"])
            return None

    results = await asyncio.gather(*[probe(i) for i in SENSITIVE])
    found = [r for r in results if r]
    checked = [{"path": p[0], "exposed": any(f.title == p[1] for f in found)} for p in SENSITIVE]
    if not found:
        found = [finding("files-ok", M, f"No sensitive files exposed ({len(SENSITIVE)} paths checked)", "pass",
                         evidence=", ".join(p[0] for p in SENSITIVE))]
    return found, checked


async def _check_wellknown(client: httpx.AsyncClient, base: str) -> tuple[list[Finding], dict]:
    out, info = [], {}
    try:
        s, b, c = await _snippet(client, base + "/.well-known/security.txt")
        has = s == 200 and b"Contact:" in b
    except Exception:
        has = False
    info["security_txt"] = has
    out.append(finding("security-txt", M, "security.txt published", "pass") if has else
               finding("security-txt-missing", M, "No security.txt file", "info", "info",
                       "security.txt tells researchers how to report vulnerabilities to you.",
                       remediation="Publish /.well-known/security.txt (see securitytxt.org).",
                       references=["https://securitytxt.org/"]))
    try:
        s, b, c = await _snippet(client, base + "/robots.txt")
        if s == 200 and _not_html(c, b):
            dis = re.findall(rb"(?im)^\s*disallow:\s*(\S+)", b)
            info["robots_disallow"] = [d.decode("utf-8", "replace") for d in dis[:30]]
            interesting = [d for d in info["robots_disallow"]
                           if re.search(r"admin|backup|private|secret|config|internal|staging|\.sql|\.bak", d, re.I)]
            if interesting:
                out.append(finding("robots-sensitive", M, "robots.txt reveals sensitive paths", "warn", "low",
                                   "robots.txt is public; listing sensitive paths advertises them to attackers.",
                                   evidence="\n".join(interesting[:10]),
                                   remediation="Protect these paths with authentication instead of hiding them via robots.txt."))
    except Exception:
        pass
    return out, info


async def scan_exposure(target: Target, client: httpx.AsyncClient, main: httpx.Response | None,
                        https_ok: bool) -> dict[str, Any]:
    out: list[Finding] = []
    data: dict[str, Any] = {}
    final = main.url if main is not None else httpx.URL(target.url)
    base = f"{final.scheme}://{final.netloc.decode()}"

    tasks = [
        _check_redirect(client, target, https_ok),
        _check_cors(client, str(final)),
        _check_files(client, base),
        _check_wellknown(client, base),
    ]
    redirect, cors, (files, checked), (wk, wk_info) = await asyncio.gather(*tasks)
    out += redirect + cors + files + wk
    data["paths_checked"] = checked
    data.update(wk_info)

    if main is not None:
        out += _check_cookies(main)
        body = main.text[:4000] if "html" in main.headers.get("content-type", "") else ""
        if re.search(r"<title>\s*Index of /", body, re.I):
            out.append(finding("dir-listing", M, "Directory listing enabled", "fail", "medium",
                               "The server lists directory contents, exposing files that were never meant to be linked.",
                               remediation="Disable autoindex (nginx `autoindex off;`, Apache `Options -Indexes`)."))
    return {"findings": out, "data": data}
