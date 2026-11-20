"""TCP port scan of common services with light banner grabbing."""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ..models import Finding, finding
from .target import Target

M = "ports"

# port: (service, severity if exposed, why it matters)
COMMON_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "high", "FTP sends credentials in clear text and is often misconfigured for anonymous access."),
    22: ("SSH", "info", "SSH is expected on servers; ensure key-only auth and rate limiting."),
    23: ("Telnet", "critical", "Telnet is unencrypted remote shell access."),
    25: ("SMTP", "low", "Mail server exposed; verify it is not an open relay."),
    53: ("DNS", "low", "DNS service exposed; verify recursion is disabled for the internet."),
    80: ("HTTP", "info", "Web server (plain HTTP)."),
    110: ("POP3", "medium", "POP3 may allow clear-text authentication."),
    111: ("RPCbind", "high", "RPC portmapper leaks service info and is a frequent attack vector."),
    135: ("MS-RPC", "high", "Windows RPC should never be internet-facing."),
    139: ("NetBIOS", "high", "NetBIOS session service should never be internet-facing."),
    143: ("IMAP", "medium", "IMAP may allow clear-text authentication."),
    443: ("HTTPS", "info", "Web server (TLS)."),
    445: ("SMB", "critical", "SMB exposed to the internet (WannaCry / EternalBlue class attacks)."),
    993: ("IMAPS", "info", "Encrypted IMAP."),
    995: ("POP3S", "info", "Encrypted POP3."),
    1433: ("MSSQL", "high", "Database servers should not be reachable from the internet."),
    1521: ("Oracle DB", "high", "Database servers should not be reachable from the internet."),
    2375: ("Docker API", "critical", "Unauthenticated Docker API gives full host takeover."),
    3000: ("Dev server", "low", "Common development server port; may expose a debug app."),
    3306: ("MySQL", "high", "Database servers should not be reachable from the internet."),
    3389: ("RDP", "high", "Remote Desktop is a top ransomware entry point."),
    5432: ("PostgreSQL", "high", "Database servers should not be reachable from the internet."),
    5900: ("VNC", "high", "VNC is frequently weakly authenticated."),
    6379: ("Redis", "critical", "Redis has no auth by default and allows remote code execution."),
    8000: ("HTTP-alt", "low", "Alternate HTTP port; often a dev or admin service."),
    8080: ("HTTP-proxy", "low", "Alternate HTTP port; often an admin panel or proxy."),
    8443: ("HTTPS-alt", "low", "Alternate HTTPS port; often an admin panel."),
    9200: ("Elasticsearch", "critical", "Elasticsearch without auth leaks entire datasets."),
    11211: ("Memcached", "high", "Memcached can leak data and be abused for DDoS amplification."),
    27017: ("MongoDB", "critical", "MongoDB exposed to the internet is a classic data-breach source."),
}

# Protocols whose servers greet first. A connect that yields no greeting on these
# is usually a firewall / antivirus proxy accepting on the server's behalf.
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 5900}

CONNECT_TIMEOUT = 1.6
BANNER_TIMEOUT = 2.5
CONCURRENCY = 40


async def _probe(ip: str, port: int, sem: asyncio.Semaphore) -> dict[str, Any] | None:
    async with sem:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return None
        latency = round((time.perf_counter() - start) * 1000, 1)
        banner = ""
        if port not in (80, 443, 8080, 8443, 8000, 3000):
            try:
                raw = await asyncio.wait_for(reader.read(160), BANNER_TIMEOUT)
                banner = raw.decode("latin-1", "replace").strip().splitlines()[0][:120] if raw else ""
            except (OSError, asyncio.TimeoutError, IndexError):
                banner = ""
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except Exception:
            pass
        return {"port": port, "latency_ms": latency, "banner": banner}


async def scan_ports(target: Target) -> dict[str, Any]:
    ip = target.addresses[0]
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*[_probe(ip, p, sem) for p in COMMON_PORTS])
    open_ports = sorted((r for r in results if r), key=lambda r: r["port"])

    out: list[Finding] = []
    table = []
    for r in open_ports:
        service, sev, why = COMMON_PORTS[r["port"]]
        confirmed = not (r["port"] in BANNER_PORTS and not r["banner"])
        table.append({**r, "service": service, "risk": sev if confirmed else "info", "confirmed": confirmed})
        if sev == "info" or not confirmed:
            continue
        out.append(finding(
            f"port-{r['port']}", M, f"{service} exposed on port {r['port']}/tcp",
            "fail" if sev in ("critical", "high", "medium") else "warn", sev, why,
            evidence=f"{ip}:{r['port']} open ({r['latency_ms']} ms)" + (f"\nBanner: {r['banner']}" if r["banner"] else ""),
            remediation=f"If {service} does not need to be public, block port {r['port']} at the firewall / "
                        "security group, bind it to localhost or a private network, and require strong auth.",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html"]))

    unconfirmed = [t for t in table if not t["confirmed"]]
    if unconfirmed:
        out.append(finding(
            "ports-unconfirmed", M, "Some ports accepted connections without a service banner", "info", "info",
            "These ports completed a TCP handshake but never sent the greeting their protocol requires. "
            "This is typical of a firewall or proxy between the scanner and the target, so they are not "
            "counted as exposures.",
            evidence=", ".join(f"{t['port']}/{t['service']}" for t in unconfirmed)))
    risky = [t for t in table if t["risk"] != "info"]
    if not risky:
        out.append(finding("ports-ok", M, "No high-risk services exposed", "pass",
                           evidence=f"{len(table)} open of {len(COMMON_PORTS)} probed: "
                                    + (", ".join(f"{t['port']}/{t['service']}" for t in table if t["confirmed"]) or "none")))
    return {"findings": out, "data": {"ip": ip, "probed": len(COMMON_PORTS), "open": table}}
