"""HTTP security header analysis."""
from __future__ import annotations

import re

import httpx

from ..models import Finding, finding

M = "headers"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP = "https://owasp.org/www-project-secure-headers/"


def analyze_headers(resp: httpx.Response) -> list[Finding]:
    h = resp.headers
    is_https = resp.url.scheme == "https"
    out: list[Finding] = []

    # --- Content-Security-Policy -------------------------------------------
    csp = h.get("content-security-policy")
    csp_ro = h.get("content-security-policy-report-only")
    if not csp:
        out.append(finding(
            "csp-missing", M, "Content-Security-Policy header missing", "fail", "medium",
            "Without a CSP the browser will execute any injected script, making XSS far more damaging.",
            evidence=f"Report-Only policy present: {csp_ro}" if csp_ro else "Header not present",
            remediation="Define a restrictive policy, e.g. `Content-Security-Policy: default-src 'self'; "
                        "object-src 'none'; base-uri 'self'; frame-ancestors 'self'` and tighten from there.",
            references=[MDN + "Content-Security-Policy", OWASP]))
    else:
        weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in csp]
        wildcard = re.search(r"(script-src|default-src)[^;]*\s\*(\s|;|$)", csp)
        if weak or wildcard:
            issues = weak + (["wildcard (*) source"] if wildcard else [])
            out.append(finding(
                "csp-weak", M, "Content-Security-Policy allows unsafe sources", "warn", "medium",
                "The CSP is present but permits " + ", ".join(issues) + ", which weakens XSS protection.",
                evidence=csp,
                remediation="Replace 'unsafe-inline' with nonces or hashes, remove 'unsafe-eval' and avoid wildcard sources.",
                references=[MDN + "Content-Security-Policy"]))
        else:
            out.append(finding("csp-ok", M, "Content-Security-Policy configured", "pass", evidence=csp))

    # --- HSTS -------------------------------------------------------------
    hsts = h.get("strict-transport-security")
    if is_https:
        if not hsts:
            out.append(finding(
                "hsts-missing", M, "Strict-Transport-Security header missing", "fail", "medium",
                "Browsers may connect over plain HTTP first, allowing SSL-stripping man-in-the-middle attacks.",
                evidence="Header not present",
                remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (add `preload` once ready).",
                references=[MDN + "Strict-Transport-Security"]))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age < 15552000:
                out.append(finding(
                    "hsts-short", M, "HSTS max-age is too short", "warn", "low",
                    f"max-age is {max_age} seconds; at least 6 months (15552000) is recommended.",
                    evidence=hsts, remediation="Raise max-age to 31536000 (one year).",
                    references=[MDN + "Strict-Transport-Security"]))
            else:
                out.append(finding("hsts-ok", M, "HSTS enabled with a long max-age", "pass", evidence=hsts))
            if "includesubdomains" not in hsts.lower():
                out.append(finding(
                    "hsts-subdomains", M, "HSTS does not cover subdomains", "info", "info",
                    "includeSubDomains is not set, so subdomains are not protected by this policy.",
                    evidence=hsts, remediation="Add `includeSubDomains` once every subdomain serves HTTPS."))

    # --- Clickjacking -------------------------------------------------------
    xfo = h.get("x-frame-options")
    fa = csp and "frame-ancestors" in csp
    if not xfo and not fa:
        out.append(finding(
            "clickjacking", M, "No clickjacking protection", "fail", "medium",
            "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed by any site.",
            evidence="X-Frame-Options and frame-ancestors absent",
            remediation="Send `X-Frame-Options: DENY` (or SAMEORIGIN) and/or `Content-Security-Policy: frame-ancestors 'self'`.",
            references=[MDN + "X-Frame-Options"]))
    else:
        out.append(finding("clickjacking-ok", M, "Clickjacking protection present", "pass",
                           evidence=xfo or "CSP frame-ancestors"))

    # --- Simple headers -----------------------------------------------------
    xcto = h.get("x-content-type-options")
    if (xcto or "").lower() != "nosniff":
        out.append(finding(
            "xcto-missing", M, "X-Content-Type-Options not set to nosniff", "fail", "low",
            "Browsers may MIME-sniff responses and execute content as a different type.",
            evidence=xcto or "Header not present",
            remediation="Add `X-Content-Type-Options: nosniff`.",
            references=[MDN + "X-Content-Type-Options"]))
    else:
        out.append(finding("xcto-ok", M, "X-Content-Type-Options: nosniff", "pass", evidence=xcto))

    rp = h.get("referrer-policy")
    if not rp:
        out.append(finding(
            "referrer-missing", M, "Referrer-Policy header missing", "fail", "low",
            "Full URLs (which may contain tokens or IDs) can leak to third-party sites via the Referer header.",
            evidence="Header not present",
            remediation="Add `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`).",
            references=[MDN + "Referrer-Policy"]))
    elif rp.lower().strip() in ("unsafe-url", "no-referrer-when-downgrade"):
        out.append(finding(
            "referrer-weak", M, "Referrer-Policy is permissive", "warn", "low",
            f"'{rp}' sends the full URL to other origins.", evidence=rp,
            remediation="Use `strict-origin-when-cross-origin` or stricter."))
    else:
        out.append(finding("referrer-ok", M, "Referrer-Policy configured", "pass", evidence=rp))

    pp = h.get("permissions-policy")
    if not pp:
        out.append(finding(
            "permissions-missing", M, "Permissions-Policy header missing", "fail", "low",
            "Powerful browser features (camera, microphone, geolocation...) are not explicitly restricted.",
            evidence="Header not present",
            remediation="Add e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
            references=[MDN + "Permissions-Policy"]))
    else:
        out.append(finding("permissions-ok", M, "Permissions-Policy configured", "pass", evidence=pp))

    coop = h.get("cross-origin-opener-policy")
    if not coop:
        out.append(finding(
            "coop-missing", M, "Cross-Origin-Opener-Policy not set", "info", "info",
            "COOP isolates the browsing context from cross-origin popups (helps against XS-Leaks).",
            remediation="Consider `Cross-Origin-Opener-Policy: same-origin`.",
            references=[MDN + "Cross-Origin-Opener-Policy"]))
    else:
        out.append(finding("coop-ok", M, "Cross-Origin-Opener-Policy configured", "pass", evidence=coop))

    # --- Information disclosure -------------------------------------------
    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        v = h.get(name)
        if v and (name != "server" or re.search(r"\d", v)):
            leaks.append(f"{name}: {v}")
    if leaks:
        out.append(finding(
            "version-disclosure", M, "Server software version disclosed", "fail", "low",
            "Response headers reveal software names/versions, helping attackers find matching exploits.",
            evidence="\n".join(leaks),
            remediation="Remove or genericise these headers (e.g. `server_tokens off;` in nginx, "
                        "`ServerTokens Prod` in Apache, `app.disable('x-powered-by')` in Express).",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"]))
    else:
        out.append(finding("version-ok", M, "No version numbers in response headers", "pass"))

    return out
