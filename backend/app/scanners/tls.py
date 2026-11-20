"""SSL/TLS configuration and certificate analysis."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import Finding, finding
from .target import Target

M = "tls"
TIMEOUT = 10

PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon")


def _handshake(host: str, ip: str, port: int, verify: bool,
               version: ssl.TLSVersion | None = None) -> dict[str, Any]:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
            if version < ssl.TLSVersion.TLSv1_2:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError) as exc:
            return {"ok": False, "error": f"client-unsupported: {exc}", "client_unsupported": True}
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return {
                    "ok": True,
                    "version": tls.version(),
                    "cipher": tls.cipher(),
                    "der": tls.getpeercert(binary_form=True),
                }
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "verify_error": exc.verify_message or str(exc), "error": str(exc)}
    except (TimeoutError, socket.timeout) as exc:
        return {"ok": False, "error": f"timed out: {exc}", "timeout": True}
    except (ssl.SSLError, OSError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _handshake_retry(*args) -> dict[str, Any]:
    res = _handshake(*args)
    if not res["ok"] and (res.get("timeout") or "reset" in res.get("error", "").lower()):
        res = _handshake(*args)
    return res


def _name(n: x509.Name, oid) -> str | None:
    vals = n.get_attributes_for_oid(oid)
    return vals[0].value if vals else None


def _parse_cert(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_size = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_size = f"EC ({key.curve.name})", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_size = "DSA", key.key_size
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_type, key_size = type(key).__name__.replace("PublicKey", ""), 256
    else:
        key_type, key_size = type(key).__name__, 0
    try:
        sans = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc
    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    return {
        "subject": _name(cert.subject, NameOID.COMMON_NAME) or cert.subject.rfc4514_string(),
        "issuer": _name(cert.issuer, NameOID.ORGANIZATION_NAME) or _name(cert.issuer, NameOID.COMMON_NAME)
                  or cert.issuer.rfc4514_string(),
        "issuer_cn": _name(cert.issuer, NameOID.COMMON_NAME),
        "self_signed": cert.issuer == cert.subject,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
        "serial": format(cert.serial_number, "x"),
        "key_type": key_type,
        "key_size": key_size,
        "signature_hash": sig_hash,
        "sans": sans[:50],
        "san_count": len(sans),
    }


async def scan_tls(target: Target) -> dict[str, Any]:
    host, ip, port = target.host, target.addresses[0], target.tls_port
    out: list[Finding] = []
    data: dict[str, Any] = {"host": host, "ip": ip, "port": port}

    base = await asyncio.to_thread(_handshake_retry, host, ip, port, False)
    if not base["ok"]:
        if base.get("timeout"):
            out.append(finding(
                "tls-timeout", M, "TLS handshake timed out", "warn", "low",
                f"{host}:{port} accepted the connection but did not finish a TLS handshake in time. "
                "The server may be overloaded or filtering the scanner; TLS checks were skipped.",
                evidence=base.get("error")))
            data["available"] = None
            return {"findings": out, "data": data}
        out.append(finding(
            "tls-unavailable", M, "HTTPS is not available", "fail", "high",
            f"Could not complete a TLS handshake with {host}:{port}. Traffic to this site cannot be encrypted.",
            evidence=base.get("error"),
            remediation="Serve the site over HTTPS with a certificate from a trusted CA (e.g. Let's Encrypt) "
                        "and redirect all HTTP traffic to HTTPS.",
            references=["https://letsencrypt.org/getting-started/"]))
        data["available"] = False
        return {"findings": out, "data": data}

    data["available"] = True
    data["negotiated"] = {"version": base["version"], "cipher": base["cipher"][0],
                          "bits": base["cipher"][2]}
    cert = _parse_cert(base["der"])
    data["certificate"] = cert

    # --- Trust chain / hostname / expiry --------------------------------------
    verified = await asyncio.to_thread(_handshake_retry, host, ip, port, True)
    days = cert["days_left"]
    data["trusted"] = True if verified["ok"] else (False if verified.get("verify_error") else None)
    if days < 0:
        out.append(finding(
            "cert-expired", M, "Certificate has expired", "fail", "critical",
            f"The certificate expired {-days} day(s) ago. Browsers block the site with a full-page warning.",
            evidence=f"notAfter: {cert['not_after']}" + ("\n" + verified["verify_error"] if verified.get("verify_error") else ""),
            remediation="Renew the certificate immediately and automate renewal (certbot / ACME).",
            references=["https://letsencrypt.org/docs/"]))
    elif verified.get("verify_error"):
        msg = verified["verify_error"]
        low = msg.lower()
        if "self-signed" in low or "self signed" in low:
            title = "Self-signed certificate"
        elif "hostname" in low or "ip address mismatch" in low:
            title = "Certificate hostname mismatch"
        elif "local issuer" in low or "chain" in low:
            title = "Incomplete or untrusted certificate chain"
        else:
            title = "Certificate is not trusted"
        out.append(finding(
            "cert-untrusted", M, title, "fail", "high",
            "Browsers will show a full-page security warning and users are exposed to interception.",
            evidence=msg,
            remediation="Install a valid certificate for this exact hostname from a publicly trusted CA, "
                        "including the full intermediate chain.",
            references=["https://www.ssllabs.com/ssltest/"]))
    elif verified["ok"]:
        out.append(finding("cert-trusted", M, "Certificate is valid and trusted", "pass",
                           evidence=f"Issued by {cert['issuer']} for {cert['subject']}"))

    if 0 <= days < 14:
        out.append(finding("cert-expiring", M, f"Certificate expires in {days} days", "fail", "high",
                           "Renewal is urgent; an expired certificate takes the site offline for users.",
                           evidence=cert["not_after"],
                           remediation="Renew now and automate renewal (certbot / ACME)."))
    elif 14 <= days < 30:
        out.append(finding("cert-expiring", M, f"Certificate expires in {days} days", "warn", "medium",
                           "The certificate is close to expiry.", evidence=cert["not_after"],
                           remediation="Renew soon and automate renewal (certbot / ACME)."))
    elif days >= 30:
        out.append(finding("cert-expiry-ok", M, f"Certificate valid for {days} more days", "pass",
                           evidence=cert["not_after"]))

    # --- Key & signature ------------------------------------------------------
    if cert["key_type"] == "RSA" and cert["key_size"] < 2048:
        out.append(finding("weak-key", M, f"Weak RSA key ({cert['key_size']} bits)", "fail", "high",
                           "RSA keys below 2048 bits can be factored with modest resources.",
                           evidence=f"{cert['key_type']} {cert['key_size']}",
                           remediation="Re-issue the certificate with an RSA-2048+ or ECDSA P-256 key."))
    else:
        out.append(finding("key-ok", M, "Strong certificate key", "pass",
                           evidence=f"{cert['key_type']} {cert['key_size']} bits"))
    if cert["signature_hash"] in ("md5", "sha1"):
        out.append(finding("weak-signature", M, "Weak certificate signature algorithm", "fail", "medium",
                           f"The certificate is signed with {cert['signature_hash'].upper()}, which is collision-prone.",
                           evidence=cert["signature_hash"],
                           remediation="Re-issue the certificate with a SHA-256 based signature."))

    # --- Protocol versions ----------------------------------------------------
    results = await asyncio.gather(*[
        asyncio.to_thread(_handshake_retry, host, ip, port, False, ver) for _, ver in PROTOCOLS])
    protocols: dict[str, bool | None] = {}
    for (label, _), res in zip(PROTOCOLS, results):
        protocols[label] = None if (res.get("client_unsupported") or res.get("timeout")) else bool(res["ok"])
    # The base handshake proves the negotiated version is supported even if a probe flaked.
    if base["version"] in protocols:
        protocols[base["version"]] = True
    data["protocols"] = protocols

    legacy = [p for p in ("TLSv1.0", "TLSv1.1") if protocols.get(p)]
    if legacy:
        out.append(finding(
            "legacy-tls", M, f"Deprecated protocol enabled: {', '.join(legacy)}", "fail", "medium",
            "TLS 1.0 and 1.1 were deprecated by RFC 8996 and are vulnerable to downgrade attacks (BEAST, POODLE-style).",
            evidence=", ".join(legacy),
            remediation="Disable TLS 1.0/1.1; allow only TLS 1.2 and TLS 1.3 "
                        "(nginx: `ssl_protocols TLSv1.2 TLSv1.3;`).",
            references=["https://datatracker.ietf.org/doc/html/rfc8996"]))
    else:
        out.append(finding("legacy-tls-ok", M, "Legacy TLS 1.0 / 1.1 disabled", "pass"))

    if protocols.get("TLSv1.3"):
        out.append(finding("tls13", M, "TLS 1.3 supported", "pass"))
    elif protocols.get("TLSv1.3") is False:
        out.append(finding("tls13-missing", M, "TLS 1.3 not supported", "warn", "low",
                           "TLS 1.3 offers faster handshakes and removes legacy cryptography.",
                           remediation="Enable TLS 1.3 in your web server / load balancer."))

    cipher = base["cipher"][0]
    if any(m in cipher for m in WEAK_CIPHER_MARKERS):
        out.append(finding("weak-cipher", M, "Weak cipher suite negotiated", "fail", "high",
                           "The server picked a cipher considered broken.", evidence=cipher,
                           remediation="Restrict cipher suites to AEAD ciphers (AES-GCM, CHACHA20-POLY1305)."))
    else:
        out.append(finding("cipher-ok", M, "Strong cipher negotiated", "pass",
                           evidence=f"{base['version']} · {cipher} ({base['cipher'][2]} bits)"))
    return {"findings": out, "data": data}
