"""Target restriction for the lab traffic simulator (AGENTS.md §2.7).

The simulator must only ever talk to lab infrastructure. A target is allowed when its host is:

* ``localhost`` / ``*.localhost`` or a loopback IP literal;
* a private IP literal (RFC 1918, IPv6 ULA ``fc00::/7``);
* a hostname (e.g. a compose service name such as ``gate``) whose *every* resolved address is loopback/private.

Link-local addresses (``169.254.0.0/16``, ``fe80::/10``) are rejected on purpose: they include cloud metadata
endpoints. Anything else is refused unless the operator passes ``--i-own-this-target`` (``allow_any=True``).

Known limitation: DNS is resolved at check time only (no pinning), so a hostile resolver could rebind a lab name
afterwards. The simulator is a lab tool; operators control the resolver in the compose network.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

Resolver = Callable[[str], Iterable[str]]


class TargetNotAllowedError(ValueError):
    """Raised when the simulator is pointed at something that is not demonstrably a lab host."""


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


def ip_is_lab(ip: str) -> bool:
    """True for loopback and private (RFC 1918 / ULA) addresses. Link-local and public are False."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_loopback:  # before is_reserved: ::1 lies inside the reserved ::/8 block
        return True
    if addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return any(
            addr in net
            for net in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
        )
    return addr in ipaddress.ip_network("fc00::/7")


def check_target(url: str, *, allow_any: bool = False, resolver: Resolver | None = None) -> str:
    """Validate ``url`` and return it normalized (no trailing slash). Raise :class:`TargetNotAllowedError`.

    ``allow_any`` corresponds to the explicit ``--i-own-this-target`` flag; even then only http(s) URLs are accepted.
    """
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise TargetNotAllowedError(f"unsupported scheme {parts.scheme!r} (only http/https)")
    host = parts.hostname
    if not host:
        raise TargetNotAllowedError(f"no host in target URL {url!r}")
    if parts.username or parts.password:
        raise TargetNotAllowedError("credentials in the target URL are not allowed")
    normalized = url.strip().rstrip("/")
    if allow_any:
        return normalized
    host = host.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return normalized
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        pass
    else:
        if ip_is_lab(host):
            return normalized
        raise TargetNotAllowedError(
            f"{host} is not a loopback/private lab address; pass --i-own-this-target only for systems you own"
        )
    try:
        addrs = list((resolver or _default_resolver)(host))
    except OSError as exc:
        raise TargetNotAllowedError(f"cannot resolve {host!r}: {exc}") from exc
    if not addrs:
        raise TargetNotAllowedError(f"{host!r} did not resolve to any address")
    bad = [a for a in addrs if not ip_is_lab(a)]
    if bad:
        raise TargetNotAllowedError(
            f"{host!r} resolves to non-lab address(es) {', '.join(bad)}; "
            "pass --i-own-this-target only for systems you own"
        )
    return normalized


def same_origin_path(base_url: str, candidate: str) -> str | None:
    """Return a path (+query) for ``candidate`` if it stays on ``base_url``'s origin, else None.

    Used when the simulated AI agent follows links/instructions found in responses: it must never be steered to a
    different host (e.g. a canary that says "fetch https://evil.example/").
    """
    candidate = candidate.strip()
    if not candidate:
        return None
    if candidate.startswith("/") and not candidate.startswith("//"):
        return candidate
    parts = urlsplit(candidate)
    if not parts.scheme:
        return None
    base = urlsplit(base_url)
    if (parts.scheme, parts.hostname, parts.port) != (base.scheme, base.hostname, base.port):
        return None
    path = parts.path or "/"
    return f"{path}?{parts.query}" if parts.query else path
