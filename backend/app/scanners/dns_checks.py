"""DNS & email-security records (SPF, DMARC, CAA)."""
from __future__ import annotations

from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..models import Finding, finding
from .target import Target

M = "dns"


async def _txt(resolver, name: str) -> list[str]:
    try:
        ans = await resolver.resolve(name, "TXT")
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


async def _records(resolver, name: str, rtype: str) -> list[str]:
    try:
        ans = await resolver.resolve(name, rtype)
        return [r.to_text() for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _apex(host: str) -> str:
    parts = host.split(".")
    # Good-enough registrable-domain guess (handles co.uk-style 2-letter SLDs).
    if len(parts) > 2 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "ac", "gov", "edu"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


async def _caa(resolver, host: str) -> tuple[str, list[str]]:
    # CAA is inherited from parent domains, so walk up the tree.
    labels = host.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        recs = await _records(resolver, name, "CAA")
        if recs:
            return name, recs
    return "", []


async def scan_dns(target: Target) -> dict[str, Any]:
    out: list[Finding] = []
    if target.is_ip:
        out.append(finding("dns-skip", M, "DNS checks skipped for IP targets", "info", "info"))
        return {"findings": out, "data": {}}

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5
    apex = _apex(target.host)

    a = await _records(resolver, target.host, "A")
    aaaa = await _records(resolver, target.host, "AAAA")
    mx = await _records(resolver, apex, "MX")
    ns = await _records(resolver, apex, "NS")
    txt = await _txt(resolver, apex)
    dmarc = [t for t in await _txt(resolver, f"_dmarc.{apex}") if t.lower().startswith("v=dmarc1")]
    caa_at, caa = await _caa(resolver, target.host)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]

    data = {"apex": apex, "a": a, "aaaa": aaaa, "mx": mx, "ns": ns, "spf": spf, "dmarc": dmarc,
            "caa": caa, "caa_at": caa_at}

    if not spf:
        out.append(finding("spf-missing", M, f"No SPF record for {apex}", "fail", "medium",
                           "Without SPF anyone can send email that appears to come from your domain.",
                           remediation=f"Publish a TXT record on {apex}: `v=spf1 include:<your-provider> -all` "
                                       "(or `v=spf1 -all` if the domain sends no mail).",
                           references=["https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"]))
    else:
        rec = spf[0]
        if rec.rstrip().endswith("+all") or " +all" in rec:
            out.append(finding("spf-permissive", M, "SPF allows any sender (+all)", "fail", "high",
                               "+all authorises every server on the internet to send as your domain.",
                               evidence=rec, remediation="Change the qualifier to `-all` or `~all`."))
        else:
            out.append(finding("spf-ok", M, "SPF record present", "pass", evidence=rec))

    if not dmarc:
        out.append(finding("dmarc-missing", M, f"No DMARC policy for {apex}", "fail", "medium",
                           "DMARC tells receivers to reject spoofed mail and gives you abuse reports.",
                           remediation=f"Publish TXT `_dmarc.{apex}`: `v=DMARC1; p=quarantine; rua=mailto:dmarc@{apex}` "
                                       "then move to p=reject.",
                           references=["https://dmarc.org/overview/"]))
    else:
        rec = dmarc[0]
        if "p=none" in rec.replace(" ", "").lower():
            out.append(finding("dmarc-none", M, "DMARC policy is monitor-only (p=none)", "warn", "low",
                               "Spoofed mail is reported but still delivered.", evidence=rec,
                               remediation="Move to `p=quarantine` and then `p=reject` once reports look clean."))
        else:
            out.append(finding("dmarc-ok", M, "DMARC enforcement enabled", "pass", evidence=rec))

    if not caa:
        out.append(finding("caa-missing", M, "No CAA record", "info", "info",
                           "CAA restricts which certificate authorities may issue certificates for your domain.",
                           remediation=f'Add e.g. `{apex}. CAA 0 issue "letsencrypt.org"`.',
                           references=["https://letsencrypt.org/docs/caa/"]))
    else:
        out.append(finding("caa-ok", M, "CAA record restricts certificate issuance", "pass",
                           evidence=f"{caa_at}: " + "; ".join(caa[:5])))

    if aaaa:
        out.append(finding("ipv6", M, "IPv6 enabled", "pass", evidence=", ".join(aaaa[:4])))
    return {"findings": out, "data": data}
