"""Shared HTTP client that refuses to follow redirects into private networks."""
from __future__ import annotations

import httpx

from .. import config
from .target import TargetError, assert_allowed_ip, resolve


async def _guard(request: httpx.Request) -> None:
    host = request.url.host
    for ip in await resolve(host):
        assert_allowed_ip(ip)


def make_client(follow_redirects: bool = True, verify: bool = False) -> httpx.AsyncClient:
    # verify=False: certificate problems are reported by the TLS module, the
    # HTTP checks should still be able to look at the response.
    return httpx.AsyncClient(
        follow_redirects=follow_redirects,
        max_redirects=6,
        verify=verify,
        timeout=httpx.Timeout(config.HTTP_TIMEOUT, connect=config.HTTP_TIMEOUT),
        headers={"User-Agent": config.USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
        event_hooks={"request": [_guard]},
    )


async def fetch(client: httpx.AsyncClient, url: str, method: str = "GET", **kw) -> httpx.Response:
    try:
        return await client.request(method, url, **kw)
    except TargetError:
        raise
    except httpx.HTTPError as exc:
        raise ConnectionError(f"{type(exc).__name__}: {exc}") from exc
