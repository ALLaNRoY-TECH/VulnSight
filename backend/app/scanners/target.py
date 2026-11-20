"""Target parsing, DNS resolution and SSRF protection."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .. import config

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{1,63}$", re.I)


class TargetError(ValueError):
    """Raised when a target is malformed or not allowed."""


@dataclass
class Target:
    raw: str
    scheme: str
    host: str
    port: int | None
    path: str
    addresses: list[str] = field(default_factory=list)

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def base_url(self) -> str:
        port = f":{self.port}" if self.port else ""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}{port}"

    @property
    def url(self) -> str:
        return self.base_url + (self.path or "/")

    @property
    def https_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = f":{self.port}" if self.port and self.scheme == "https" else ""
        return f"https://{host}{port}{self.path or '/'}"

    @property
    def http_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = f":{self.port}" if self.port and self.scheme == "http" else ""
        return f"http://{host}{port}{self.path or '/'}"

    @property
    def tls_port(self) -> int:
        return self.port if (self.port and self.scheme == "https") else 443


def parse_target(raw: str) -> Target:
    raw = raw.strip()
    if not raw:
        raise TargetError("Target is empty.")
    candidate = raw if "://" in raw else f"https://{raw}"
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https"):
        raise TargetError("Only http:// and https:// targets are supported.")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise TargetError("Could not determine a hostname.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.match(host):
            raise TargetError(f"'{host}' is not a valid hostname.")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError("Invalid port.") from exc
    if parts.username or parts.password:
        raise TargetError("Credentials in the URL are not allowed.")
    return Target(raw=raw, scheme=parts.scheme, host=host, port=port, path=parts.path or "/")


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def assert_allowed_ip(ip: str) -> None:
    if not config.ALLOW_PRIVATE_TARGETS and not is_public_ip(ip):
        raise TargetError(
            f"{ip} is a private, loopback or reserved address. Scanning internal "
            "networks is disabled (set VULNSIGHT_ALLOW_PRIVATE=1 for local lab use)."
        )


async def resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"Could not resolve '{host}'.") from exc
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise TargetError(f"'{host}' has no addresses.")
    return seen


async def prepare_target(raw: str) -> Target:
    target = parse_target(raw)
    target.addresses = await resolve(target.host)
    for ip in target.addresses:
        assert_allowed_ip(ip)
    return target
