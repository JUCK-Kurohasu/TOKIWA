"""Validation of LLM endpoint URLs set at runtime (UI / ``PUT /llm/config``). OWNER: llm module.

Why (audit #98): the stored API key is sent to whatever ``*_base_url`` says. An admin session (or a CSRF / XSS /
insider path to one) could point the base URL at its own host or at an internal address and run the connection test:
the key leaves in a header, over plain HTTP if allowed, and the error text doubles as an internal reachability probe.

Rules for runtime-set URLs (static env / YAML values are the operator's and are not restricted here):

- ``https://`` only; ``http://`` is accepted for loopback hosts (``localhost``, 127.0.0.0/8, ``::1``) so a local
  Ollama / vLLM still works from the UI. Other plain-HTTP endpoints (e.g. ``http://ollama:11434/v1`` inside a
  compose network) must be set through env / YAML.
- link-local (169.254.0.0/16, fe80::/10 - cloud metadata lives there), unspecified (0.0.0.0/8, ``::``), multicast,
  broadcast and known metadata endpoints are refused, including numeric spellings that resolvers accept
  (``2852039166``, ``0xa9.0xfe.0xa9.0xfe``, ``::ffff:169.254.169.254``).

TODO(verify): a *hostname* that resolves to a link-local / metadata address is not caught (no DNS lookup at
validation time, and the HTTP clients resolve again later). The key binding in ``tokiwa.llm.settings`` still keeps
the stored key from being sent to a host it was not entered for. Where to adjust: :data:`METADATA_HOSTS`,
:data:`METADATA_IPS`, :data:`LOOPBACK_NAMES`.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

LOOPBACK_NAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})
METADATA_HOSTS: frozenset[str] = frozenset(
    {"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}
)
METADATA_IPS: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS / GCP / Azure / OCI (also covered by link-local)
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDS over IPv6 (a ULA, not link-local)
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
    }
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _parse_ip(host: str) -> IPAddress | None:
    """The address a resolver would use for a numeric host, including legacy IPv4 spellings."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if host and all(c in "0123456789abcdefxABCDEFX." for c in host) and any(c.isdigit() for c in host):
        try:
            # inet_aton accepts what getaddrinfo accepts: 2852039166, 0251.0376.0251.0376, 0xa9fea9fe, 169.254.43518
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def _forbidden_ip(ip: IPAddress) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _forbidden_ip(ip.ipv4_mapped)
    if ip in METADATA_IPS:
        return "cloud metadata address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_unspecified or (
        isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("0.0.0.0/8")
    ):
        return "unspecified address"
    if ip.is_multicast:
        return "multicast address"
    if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"):
        return "broadcast address"
    return None


def is_loopback_host(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    ip = _parse_ip(host)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip is not None and ip.is_loopback


def validate_runtime_base_url(url: str) -> str:
    """Return the normalized URL (no trailing slash) or raise ``ValueError`` with the reason."""
    value = url.strip()
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("must start with https:// (http:// only for localhost)")
    try:
        host = (parts.hostname or "").rstrip(".").lower()
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError as exc:
        raise ValueError(f"malformed URL: {exc}") from None
    if not host:
        raise ValueError("URL has no host")
    if host in METADATA_HOSTS:
        raise ValueError("cloud metadata endpoints are not allowed")
    ip = _parse_ip(host)
    if ip is not None:
        reason = _forbidden_ip(ip)
        if reason:
            raise ValueError(f"{reason} is not allowed as an LLM endpoint")
    if scheme == "http" and not is_loopback_host(host):
        raise ValueError(
            "plain http:// is only allowed for localhost; use https://, or set this endpoint in the environment / "
            "tokiwa.yaml instead of the UI"
        )
    return value.rstrip("/")
