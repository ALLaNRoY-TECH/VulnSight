"""Scan orchestration: runs modules concurrently, tracks progress, scores results."""
from __future__ import annotations

import asyncio
import re
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from . import storage
from .models import MODULES, SEVERITY_ORDER, SEVERITY_PENALTY, Finding, ScanRequest
from .scanners.dns_checks import scan_dns
from .scanners.exposure import scan_exposure
from .scanners.headers import analyze_headers
from .scanners.http import fetch, make_client
from .scanners.ports import scan_ports
from .scanners.target import Target, TargetError, prepare_target
from .scanners.tls import scan_tls

MODULE_LABELS = {
    "headers": "HTTP Security Headers",
    "tls": "SSL / TLS",
    "ports": "Ports & Services",
    "exposure": "Misconfiguration & Exposure",
    "dns": "DNS & Email Security",
}

# In-flight scans live here; finished scans are persisted to SQLite.
ACTIVE: dict[str, dict[str, Any]] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def score_findings(findings: list[Finding]) -> tuple[int, str, dict[str, int]]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    penalty = 0
    for f in findings:
        if f.status in ("fail", "warn"):
            counts[f.severity] += 1
            penalty += SEVERITY_PENALTY[f.severity]
    score = max(0, 100 - penalty)
    if counts["critical"]:
        score = min(score, 49)
    elif counts["high"]:
        score = min(score, 74)
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"
    return score, grade, counts


def new_scan(req: ScanRequest) -> dict[str, Any]:
    modules = [m for m in req.modules if m in MODULES] or list(MODULES)
    scan = {
        "id": uuid.uuid4().hex[:12],
        "target": req.target.strip(),
        "host": None,
        "status": "queued",
        "created_at": now(),
        "finished_at": None,
        "duration_ms": None,
        "modules": {m: "pending" for m in modules},
        "log": [],
        "progress": 0,
        "score": None,
        "grade": None,
        "counts": None,
        "findings": [],
        "data": {},
        "site": None,
        "error": None,
    }
    ACTIVE[scan["id"]] = scan
    return scan


def _log(scan: dict, msg: str, level: str = "info") -> None:
    scan["log"].append({"t": now(), "level": level, "msg": msg})


def _progress(scan: dict) -> None:
    mods = scan["modules"]
    done = sum(1 for v in mods.values() if v in ("done", "error"))
    scan["progress"] = 10 + int(88 * done / max(1, len(mods)))


async def _site_probe(scan: dict, target: Target, client: httpx.AsyncClient) -> httpx.Response | None:
    urls = [target.url]
    if "://" not in target.raw and target.scheme == "https":
        urls.append(target.http_url)  # fall back to plain HTTP for bare hostnames
    for url in urls:
        t0 = time.perf_counter()
        try:
            resp = await fetch(client, url)
        except ConnectionError as exc:
            _log(scan, f"GET {url} failed: {exc}", "warn")
            continue
        ms = round((time.perf_counter() - t0) * 1000)
        title = ""
        if "html" in resp.headers.get("content-type", ""):
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:20000], re.I | re.S)
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:140] if m else ""
        scan["site"] = {
            "requested_url": url,
            "final_url": str(resp.url),
            "status_code": resp.status_code,
            "http_version": resp.http_version,
            "response_ms": ms,
            "redirects": [str(r.url) for r in resp.history],
            "server": resp.headers.get("server"),
            "content_type": resp.headers.get("content-type"),
            "title": title,
            "headers": dict(resp.headers),
        }
        _log(scan, f"GET {url} → {resp.status_code} in {ms} ms (final: {resp.url})", "ok")
        return resp
    return None


async def run_scan(scan: dict) -> None:
    started = time.perf_counter()
    scan["status"] = "running"
    _log(scan, f"Initialising VulnSight engine for {scan['target']}")
    try:
        _log(scan, "Resolving target and validating scope…")
        target = await prepare_target(scan["target"])
        scan["host"] = target.host
        scan["data"]["target"] = {"host": target.host, "addresses": target.addresses,
                                  "scheme": target.scheme, "port": target.port}
        _log(scan, f"{target.host} resolves to {', '.join(target.addresses[:4])}", "ok")
        scan["progress"] = 5

        async with make_client() as client:
            main = await _site_probe(scan, target, client)
            scan["progress"] = 10
            https_ok = bool(main is not None and main.url.scheme == "https")
            findings: list[Finding] = []

            async def run_module(name: str):
                scan["modules"][name] = "running"
                _log(scan, f"[{name}] {MODULE_LABELS[name]} module started")
                try:
                    if name == "headers":
                        if main is None:
                            raise ConnectionError("the site did not answer HTTP(S) requests, so headers could not be read")
                        res = {"findings": analyze_headers(main), "data": {}}
                    elif name == "tls":
                        res = await scan_tls(target)
                    elif name == "ports":
                        res = await scan_ports(target)
                    elif name == "exposure":
                        res = await scan_exposure(target, client, main, https_ok)
                    else:
                        res = await scan_dns(target)
                    findings.extend(res["findings"])
                    if res.get("data"):
                        scan["data"][name] = res["data"]
                    issues = sum(1 for f in res["findings"] if f.status in ("fail", "warn"))
                    scan["modules"][name] = "done"
                    _log(scan, f"[{name}] completed — {len(res['findings'])} checks, {issues} issue(s)",
                         "warn" if issues else "ok")
                except Exception as exc:  # one module failing must not kill the scan
                    scan["modules"][name] = "error"
                    _log(scan, f"[{name}] failed: {exc}", "error")
                    if not isinstance(exc, ConnectionError):
                        traceback.print_exc()
                _progress(scan)
                # Expose partial results while the scan is still running.
                scan["findings"] = [f.model_dump() for f in _sorted(findings)]

            await asyncio.gather(*[run_module(m) for m in scan["modules"]])

        findings_sorted = _sorted(findings)
        score, grade, counts = score_findings(findings_sorted)
        scan.update(findings=[f.model_dump() for f in findings_sorted], score=score, grade=grade,
                    counts=counts, status="completed", progress=100)
        _log(scan, f"Scan complete — score {score}/100 (grade {grade})", "ok")
    except TargetError as exc:
        scan.update(status="failed", error=str(exc), progress=100)
        _log(scan, str(exc), "error")
    except Exception as exc:
        traceback.print_exc()
        scan.update(status="failed", error=f"Unexpected error: {exc}", progress=100)
        _log(scan, f"Unexpected error: {exc}", "error")
    finally:
        scan["finished_at"] = now()
        scan["duration_ms"] = round((time.perf_counter() - started) * 1000)
        storage.save(scan)
        ACTIVE.pop(scan["id"], None)


def _sorted(findings: list[Finding]) -> list[Finding]:
    status_rank = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    return sorted(findings, key=lambda f: (status_rank[f.status], SEVERITY_ORDER[f.severity], f.module))


def get_scan(scan_id: str) -> dict | None:
    return ACTIVE.get(scan_id) or storage.load(scan_id)
