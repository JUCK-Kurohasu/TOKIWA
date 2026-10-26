"""IP / CIDR lookup tables used by the gate policy.

Why a custom table instead of ``any(ip in net for net in nets)``: a policy can carry thousands of blocked
addresses (e.g. after an AI-agent campaign rotating through a cloud range) and the lookup runs on every
request. Entries are bucketed by prefix length in hash maps keyed by the masked network integer, so a lookup
is at most one dict probe per *distinct* prefix length present (<= 33 for IPv4, <= 129 for IPv6) -- independent
of the number of entries -- and naturally yields the longest-prefix (most specific) match.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable, Iterable
from typing import Generic, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_V4_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")


def parse_ip(value: str | None) -> IPAddress | None:
    """Parse a client address as seen in ASGI ``client`` / ``X-Forwarded-For``.

    Accepts ``1.2.3.4``, ``1.2.3.4:5678``, ``[::1]:80``, ``fe80::1%eth0``. IPv4-mapped IPv6 addresses
    (``::ffff:1.2.3.4``, common on dual-stack listeners) are folded to IPv4 so policies written as IPv4
    still match. Returns None for anything that is not an IP (e.g. ``unknown`` or a hostname).
    """
    if not value:
        return None
    v = value.strip()
    if v.startswith("["):
        end = v.find("]")
        if end <= 0:
            return None
        v = v[1:end]
    elif v.count(":") == 1:  # IPv4 with port
        v = v.split(":", 1)[0]
    if "%" in v:  # IPv6 zone id
        v = v.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_network(value: str) -> IPNetwork | None:
    """Parse an IP or CIDR from the policy (host bits are tolerated: ``10.0.0.5/8`` -> ``10.0.0.0/8``)."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except (ValueError, AttributeError):
        return None
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 96 and net.subnet_of(_V4_MAPPED):
        mapped = net.network_address.ipv4_mapped
        if mapped is not None:
            return ipaddress.IPv4Network((int(mapped), net.prefixlen - 96))
    return net


class IpTable(Generic[T]):
    """Longest-prefix-match table: network -> value.

    ``merge`` decides the value when the same network is listed twice (e.g. ``min`` for rate limits so the
    stricter limit wins, ``max`` for tarpit delays). Default: the first entry wins.
    """

    __slots__ = ("_dirty", "_levels", "_merge", "_order", "_size")

    def __init__(self, merge: Callable[[T, T], T] | None = None) -> None:
        self._merge = merge
        # version (4|6) -> prefixlen -> {network_int >> (bits - prefixlen): (network text, value)}
        self._levels: dict[int, dict[int, dict[int, tuple[str, T]]]] = {4: {}, 6: {}}
        self._order: dict[int, list[tuple[int, dict[int, tuple[str, T]]]]] = {4: [], 6: []}
        self._size = 0
        self._dirty = False

    @classmethod
    def build(
        cls, entries: Iterable[tuple[str, T]], merge: Callable[[T, T], T] | None = None
    ) -> tuple[IpTable[T], list[str]]:
        """Build a table, returning it together with the entries that could not be parsed."""
        table: IpTable[T] = cls(merge)
        invalid: list[str] = []
        for text, value in entries:
            if not table.add(text, value):
                invalid.append(text)
        table.freeze()
        return table, invalid

    def add(self, text: str, value: T) -> bool:
        net = parse_network(text)
        if net is None:
            return False
        bits = net.max_prefixlen
        key = int(net.network_address) >> (bits - net.prefixlen) if net.prefixlen else 0
        level = self._levels[net.version].setdefault(net.prefixlen, {})
        existing = level.get(key)
        if existing is None:
            level[key] = (str(net), value)
            self._size += 1
            self._dirty = True
        elif self._merge is not None:
            level[key] = (existing[0], self._merge(existing[1], value))
        return True

    def freeze(self) -> None:
        """Precompute the longest-first iteration order (call after the last ``add``)."""
        self._order = {
            version: sorted(levels.items(), key=lambda kv: kv[0], reverse=True)
            for version, levels in self._levels.items()
        }
        self._dirty = False

    def lookup(self, ip: IPAddress | None) -> tuple[str, T] | None:
        """Most specific ``(network, value)`` containing ``ip``, or None."""
        if ip is None or not self._size:
            return None
        if self._dirty:  # add() used without freeze()
            self.freeze()
        order = self._order[ip.version]
        n = int(ip)
        bits = ip.max_prefixlen
        for prefixlen, level in order:
            hit = level.get(n >> (bits - prefixlen) if prefixlen else 0)
            if hit is not None:
                return hit
        return None

    def __contains__(self, ip: object) -> bool:
        if isinstance(ip, str):
            ip = parse_ip(ip)
        if not isinstance(ip, ipaddress.IPv4Address | ipaddress.IPv6Address):
            return False
        return self.lookup(ip) is not None

    def __len__(self) -> int:
        return self._size

    def __bool__(self) -> bool:
        return self._size > 0
