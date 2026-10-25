"""Outbound HTTP for notification channels and the ``webhook`` response executor, with an SSRF guard.

Why a guard: webhook URLs are configured by admins, but TOKIWA sits next to internal services (lab apps,
the Gate, cloud metadata endpoints). A mistyped or malicious URL must not turn the server into a proxy into
private networks. The guard checks scheme, an optional host allow-list, and (optionally) that every address
the host resolves to is publicly routable. Redirects are never followed (a public host could otherwise
bounce the request to a private one).

Residual risk (documented in docs/response.md): DNS rebinding between our resolution and httpx's own
connection. Use ``allowed_hosts`` for strict deployments.

Error messages raised from here are safe to show in the API: they never contain the URL path/query (Slack /
Discord webhook URLs embed their secret in the path).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import Any
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class OutboundBlocked(Exception):
    """The destination was refused by policy (scheme / allow-list / private address)."""


class DeliveryError(Exception):
    """Delivery failed (transport error or non-2xx). The message is safe to display."""


def host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    """``example.com`` matches exactly; ``.example.com`` matches the domain and any subdomain."""
    if not allowed_hosts:
        return True
    h = host.lower().rstrip(".")
    for entry in allowed_hosts:
        e = entry.strip().lower().rstrip(".")
        if not e:
            continue
        if e.startswith("."):
            if h == e[1:] or h.endswith(e):
                return True
        elif h == e:
            return True
    return False


def is_public_address(ip: IPAddress) -> bool:
    """True only for globally routable unicast addresses (handles IPv4-mapped IPv6)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast


async def _resolve(host: str, port: int) -> list[str]:
    """Resolve a hostname to addresses. Tests monkeypatch this (no DNS / network in tests)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def safe_url_label(url: str) -> str:
    """``scheme://host[:port]`` only - for logs and error messages (never the secret-bearing path)."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or "?"
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "<invalid url>"
    return f"{parts.scheme}://{host}{port}"


async def check_url(url: str, *, allowed_hosts: list[str], block_private: bool) -> None:
    """Raise :class:`OutboundBlocked` unless ``url`` is an acceptable outbound destination."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise OutboundBlocked("invalid URL") from exc
    if parts.scheme not in ("http", "https"):
        raise OutboundBlocked("URL scheme must be http or https")
    host = parts.hostname
    if not host:
        raise OutboundBlocked("URL has no host")
    if not host_allowed(host, allowed_hosts):
        raise OutboundBlocked(f"host {host!r} is not in the allowed host list")
    if not block_private:
        return
    try:
        literal: IPAddress | None = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    addrs: list[IPAddress]
    if literal is not None:
        addrs = [literal]
    else:
        try:
            resolved = await _resolve(host, port or (443 if parts.scheme == "https" else 80))
        except OSError as exc:
            raise OutboundBlocked(f"cannot resolve host {host!r}") from exc
        addrs = []
        for raw in resolved:
            try:
                addrs.append(ipaddress.ip_address(raw.split("%", 1)[0]))
            except ValueError:
                continue
    if not addrs:
        raise OutboundBlocked(f"host {host!r} did not resolve to any address")
    for addr in addrs:
        if not is_public_address(addr):
            raise OutboundBlocked(f"host {host!r} resolves to non-public address {addr}")


async def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    allowed_hosts: list[str],
    block_private: bool,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> int:
    """POST JSON after the SSRF check. Returns the HTTP status; raises OutboundBlocked / DeliveryError."""
    await check_url(url, allowed_hosts=allowed_hosts, block_private=block_private)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.post(url, json=payload, headers=headers or {})
    except httpx.HTTPError as exc:
        # httpx messages may include the full URL (with its secret path): report the type only.
        log.warning("outbound POST to %s failed: %s", safe_url_label(url), type(exc).__name__)
        raise DeliveryError(f"request failed: {type(exc).__name__}") from None
    if not 200 <= resp.status_code < 300:
        log.warning("outbound POST to %s returned HTTP %s", safe_url_label(url), resp.status_code)
        raise DeliveryError(f"HTTP {resp.status_code}")
    return resp.status_code
