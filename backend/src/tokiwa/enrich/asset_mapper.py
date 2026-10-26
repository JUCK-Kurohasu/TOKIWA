"""Asset mapper: sets ``event.asset_id`` from the event's target (destination IP / hostname / Host header / host).

Why: detectors and correlation need to know *which of our assets* an event touches, e.g. the vuln_exposure
detector raises a critical alert when an attack hits an asset with an open KEV / high-EPSS vulnerability match.

Lookup order (first hit wins): destination.ip, destination.hostname, http.host, host.name, host.ip[*], and
source.ip for outbound connections. Asset ``ips`` may hold single addresses or CIDRs (most specific wins).

The index is cached in memory and reloaded every :data:`REFRESH_SECONDS` or immediately after
:func:`invalidate_asset_index` (called by the assets API on create/update/delete). Never raises.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field

from sqlalchemy import select

from tokiwa.db.models.intel import AssetRow
from tokiwa.db.session import session_scope
from tokiwa.enrich.base import Enricher, register_enricher
from tokiwa.schemas.events import Event

log = logging.getLogger(__name__)

REFRESH_SECONDS = 60.0

_generation = 0

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def invalidate_asset_index() -> None:
    """Force every AssetMapper to reload the index on its next batch."""
    global _generation
    _generation += 1


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    s = value.strip()
    if s.startswith("[") and "]" in s:  # [v6]:port
        s = s[1 : s.index("]")]
    s = s.split("%", 1)[0]  # zone id
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _norm_host(value: str | None) -> str | None:
    if not value:
        return None
    s = value.strip().lower().rstrip(".")
    if s.startswith("["):
        return s  # bracketed IPv6 literal, handled by the IP path
    if s.count(":") == 1:  # host:port
        s = s.split(":", 1)[0]
    return s or None


@dataclass
class AssetIndex:
    by_ip: dict[str, str] = field(default_factory=dict)
    by_host: dict[str, str] = field(default_factory=dict)
    networks: list[tuple[IPNetwork, str]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.by_ip or self.by_host or self.networks)

    @classmethod
    def build(cls, rows: list[tuple[str, str | None, list[str] | None]]) -> AssetIndex:
        idx = cls()
        for asset_id, hostname, ips in rows:
            host = _norm_host(hostname)
            if host:
                idx.by_host.setdefault(host, asset_id)
            for raw in ips or []:
                if not isinstance(raw, str) or not raw.strip():
                    continue
                if "/" in raw:
                    try:
                        idx.networks.append((ipaddress.ip_network(raw.strip(), strict=False), asset_id))
                    except ValueError:
                        continue
                    continue
                ip = _parse_ip(raw)
                if ip is not None:
                    idx.by_ip.setdefault(str(ip), asset_id)
        idx.networks.sort(key=lambda item: item[0].prefixlen, reverse=True)
        return idx

    def lookup_ip(self, value: str | None) -> str | None:
        ip = _parse_ip(value)
        if ip is None:
            return None
        hit = self.by_ip.get(str(ip))
        if hit:
            return hit
        for net, asset_id in self.networks:
            if ip.version == net.version and ip in net:
                return asset_id
        return None

    def lookup_host(self, value: str | None) -> str | None:
        host = _norm_host(value)
        if not host:
            return None
        return self.by_host.get(host) or self.lookup_ip(host)

    def lookup_event(self, e: Event) -> str | None:
        if e.destination is not None:
            hit = self.lookup_ip(e.destination.ip) or self.lookup_host(e.destination.hostname)
            if hit:
                return hit
        if e.http is not None:
            hit = self.lookup_host(e.http.host)
            if hit:
                return hit
        if e.host is not None:
            hit = self.lookup_host(e.host.name)
            if hit:
                return hit
            for ip in e.host.ip:
                hit = self.lookup_ip(ip)
                if hit:
                    return hit
        if (
            e.network is not None
            and (e.network.direction or "").lower() == "outbound"
            and e.source is not None
        ):
            return self.lookup_ip(e.source.ip)
        return None


@register_enricher
class AssetMapper(Enricher):
    id = "asset_mapper"
    order = 40  # after sessionization, before detection (all enrichers run before detection)

    def __init__(self) -> None:
        self._index: AssetIndex | None = None
        self._loaded_at = 0.0
        self._generation = -1

    async def _get_index(self) -> AssetIndex | None:
        stale = time.monotonic() - self._loaded_at > REFRESH_SECONDS
        if self._index is None or stale or self._generation != _generation:
            generation = _generation
            try:
                async with session_scope() as session:
                    rows = (await session.execute(select(AssetRow.id, AssetRow.hostname, AssetRow.ips))).all()
                self._index = AssetIndex.build([(r[0], r[1], r[2]) for r in rows])
                self._generation = generation
            except Exception:
                log.exception("asset_mapper: failed to load assets (keeping previous index)")
            self._loaded_at = time.monotonic()
        return self._index

    async def enrich(self, events: list[Event]) -> None:
        if not events:
            return
        index = await self._get_index()
        if index is None or index.empty:
            return
        for e in events:
            if e.asset_id:
                continue
            try:
                asset_id = index.lookup_event(e)
            except Exception:
                log.debug("asset_mapper: lookup failed for event %s", e.id, exc_info=True)
                continue
            if asset_id:
                e.asset_id = asset_id
