"""Offline unit tests — no network access required."""
import os
import tempfile

os.environ["VULNSIGHT_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.engine import score_findings  # noqa: E402
from app.main import app  # noqa: E402
from app.models import finding  # noqa: E402
from app.scanners.exposure import _check_cookies  # noqa: E402
from app.scanners.headers import analyze_headers  # noqa: E402
from app.scanners.target import TargetError, is_public_ip, parse_target  # noqa: E402


def resp(headers: dict, url="https://example.com/") -> httpx.Response:
    return httpx.Response(200, headers=headers, request=httpx.Request("GET", url))


def ids(findings):
    return {f.id for f in findings}


# ---------------------------------------------------------------- target parsing
def test_parse_bare_host_defaults_to_https():
    t = parse_target("Example.COM")
    assert (t.scheme, t.host, t.path) == ("https", "example.com", "/")


def test_parse_url_with_port_and_path():
    t = parse_target("http://example.com:8080/app")
    assert t.port == 8080 and t.path == "/app" and t.http_url == "http://example.com:8080/app"


@pytest.mark.parametrize("bad", ["ftp://example.com", "https://user:pw@example.com", "exa mple.com", "   "])
def test_parse_rejects_bad_targets(bad):
    with pytest.raises(TargetError):
        parse_target(bad)


@pytest.mark.parametrize("ip,public", [("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False),
                                       ("169.254.169.254", False), ("192.168.1.1", False), ("::1", False),
                                       ("::ffff:10.0.0.1", False)])
def test_ssrf_guard(ip, public):
    assert is_public_ip(ip) is public


# ---------------------------------------------------------------- headers
def test_missing_headers_are_flagged():
    f = analyze_headers(resp({"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4"}))
    assert {"csp-missing", "hsts-missing", "clickjacking", "xcto-missing", "referrer-missing",
            "permissions-missing", "version-disclosure"} <= ids(f)


def test_hardened_headers_pass():
    f = analyze_headers(resp({
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "cross-origin-opener-policy": "same-origin",
        "server": "nginx",
    }))
    assert all(x.status == "pass" for x in f), [(x.id, x.status) for x in f]


def test_weak_csp_and_short_hsts():
    f = analyze_headers(resp({"content-security-policy": "script-src 'self' 'unsafe-inline'",
                              "strict-transport-security": "max-age=300"}))
    assert {"csp-weak", "hsts-short"} <= ids(f)


def test_hsts_not_required_over_http():
    f = analyze_headers(resp({}, url="http://example.com/"))
    assert "hsts-missing" not in ids(f)


# ---------------------------------------------------------------- cookies
def test_insecure_cookie_detected():
    r = httpx.Response(200, headers=[("set-cookie", "session=abc; Path=/")],
                       request=httpx.Request("GET", "https://example.com/"))
    out = _check_cookies(r)
    assert out[0].id == "cookie-flags" and "Secure" in out[0].evidence


def test_secure_cookie_passes():
    r = httpx.Response(200, headers=[("set-cookie", "s=1; Secure; HttpOnly; SameSite=Lax")],
                       request=httpx.Request("GET", "https://example.com/"))
    assert _check_cookies(r)[0].status == "pass"


# ---------------------------------------------------------------- scoring
def test_scoring_and_grade_caps():
    assert score_findings([])[:2] == (100, "A+")
    crit = [finding("x", "tls", "x", "fail", "critical")]
    score, grade, counts = score_findings(crit)
    assert score <= 49 and grade == "F" and counts["critical"] == 1
    passes = [finding("p", "tls", "p", "pass", "high")]
    assert score_findings(passes)[0] == 100  # passed checks never cost points


# ---------------------------------------------------------------- API
def test_api_health_and_validation():
    with TestClient(app) as c:
        assert c.get("/api/health").json()["status"] == "ok"
        assert c.post("/api/scans", json={"target": "example.com"}).status_code == 400  # not authorised
        assert c.post("/api/scans", json={"target": "ftp://x.com", "authorized": True}).status_code == 422
        r = c.post("/api/scans", json={"target": "127.0.0.1", "authorized": True})
        assert r.status_code == 422 and "private" in r.json()["detail"]  # SSRF guard
        assert c.get("/api/scans/doesnotexist").status_code == 404
        r = c.get("/api/health")
        assert r.headers["x-frame-options"] == "DENY"
