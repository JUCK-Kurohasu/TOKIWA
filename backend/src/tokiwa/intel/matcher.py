"""Asset software <-> vulnerability matcher.

Answers "which of *our* assets are affected by this vulnerability?" and records every answer in ``vuln_matches``
with a ``confidence`` and a human-readable ``reason`` (so an analyst can see *why* TOKIWA thinks so).

Matching strategy (best match per (vuln, asset) wins):

1. **CPE** - when the vulnerability's affected entry has a CPE 2.3 (or 2.2 URI) and the asset software has a
   vendor (explicit or from its own CPE): part/vendor/product are compared with CPE wildcard semantics (``*`` =
   ANY, ``-`` = NA, ``?``/``*`` inside values), then the version is checked against the range.
2. **Name fallback** - normalized product names (lower case, punctuation folded, vendor prefix stripped, a small
   alias table) + vendor/ecosystem agreement + the same version check. Lower confidence than CPE.

Version ranges are read leniently from the affected entries because several feeds contribute them
(intel-feeds owns the mapping). Accepted keys on an ``affected`` dict:

- NVD cpeMatch style: ``versionStartIncluding|versionStartExcluding|versionEndIncluding|versionEndExcluding``
  (snake_case variants too) and ``vulnerable: false`` to skip platform-only entries;
- OSV style: ``introduced`` / ``fixed`` / ``last_affected`` at top level, ``ranges: [{type, events: [...]}]``
  and an explicit ``versions: [...]`` list;
- ``version``: exact version, ``*``/missing (= all versions), a glob (``2.4.*``) or a constraint expression
  (``>=2.4.0,<2.4.59`` / ``<1.2 || >=2.0,<2.1``).

Version comparison uses a small self-contained comparator (:func:`compare_versions`) that understands
dotted numbers, epochs (``1:2.3``), pre-releases (``1.0rc1 < 1.0``), post/patch suffixes (``8.0p1 > 8.0``),
OpenSSL letters (``1.1.1w > 1.1.1``) and distro revisions (``2.4.58-1ubuntu1 > 2.4.58``). ``packaging`` is only a
dev dependency (via pytest), so it is not used at runtime. When a comparison is impossible the match is kept
with a *low* confidence instead of being silently dropped.

Confidence levels are module constants below - adjust them there.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from pydantic import BaseModel
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.bus import bus
from tokiwa.db.models.intel import AssetRow, VulnMatchRow, VulnRow
from tokiwa.db.session import session_scope
from tokiwa.runtime import on_startup, periodic
from tokiwa.schemas.intel import MatchStatus, VulnMatch
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------------------------------------------

CONF_EXACT = 0.95  # CPE + exact version
CONF_RANGE = 0.9  # CPE + version inside a parsed range
CONF_ALL_VERSIONS_CPE = 0.6  # CPE says every version is affected
CONF_ALL_VERSIONS_NAME = 0.5  # name-only entry without any version information
CONF_INCONCLUSIVE = 0.35  # version strings could not be compared
CONF_UNKNOWN_VERSION = 0.3  # the asset does not record a version
PENALTY_NAME_CONFIRMED = 0.15  # name match, vendor or ecosystem agree
PENALTY_NAME_ONLY = 0.25  # name match, neither vendor nor ecosystem known on both sides
MIN_CONFIDENCE = 0.2  # matches below this are not stored

AUTO_CLOSED_PREFIX = "[auto-closed] "

# Products too generic to match on name alone (without vendor/ecosystem agreement).
GENERIC_PRODUCTS = frozenset(
    {
        "admin",
        "agent",
        "api",
        "app",
        "application",
        "client",
        "common",
        "core",
        "database",
        "firmware",
        "framework",
        "gateway",
        "lib",
        "library",
        "manager",
        "os",
        "plugin",
        "portal",
        "proxy",
        "router",
        "server",
        "service",
        "util",
        "utils",
        "web",
    }
)

# Product name aliases (normalized form -> canonical CPE-style product). Extend as needed.
PRODUCT_ALIASES = {
    "httpd": "http_server",
    "apache2": "http_server",
    "apache_httpd": "http_server",
    "apache_http_server": "http_server",
    "nodejs": "node_js",
    "postgres": "postgresql",
    "openssh_server": "openssh",
    "openssh_client": "openssh",
    "mysql_server": "mysql",
    "log4j_core": "log4j",
}

# Corporate suffix/prefix tokens stripped from vendor names ("The Apache Software Foundation" -> "apache").
_VENDOR_NOISE = frozenset(
    {"the", "inc", "corp", "corporation", "ltd", "llc", "co", "gmbh", "project", "foundation", "software"}
)
VENDOR_ALIASES = {"f5_networks": "f5", "nginx_inc": "f5", "nginx": "f5"}  # NVD moved nginx:nginx -> f5:nginx

# ---------------------------------------------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------------------------------------------

_PRE_RANK = {
    "dev": 0,
    "snapshot": 0,
    "nightly": 0,
    "alpha": 1,
    "a": 1,
    "ea": 1,
    "beta": 2,
    "b": 2,
    "milestone": 2,
    "m": 2,
    "preview": 3,
    "pre": 3,
    "c": 4,
    "rc": 4,
    "cr": 4,
}
_ALWAYS_PRE = frozenset(
    {"dev", "snapshot", "nightly", "alpha", "ea", "beta", "milestone", "preview", "pre", "rc", "cr"}
)
# Single letters are pre-releases only when a number follows ("1.0a1"); "1.1.1a" (OpenSSL) is a post-release.
_SINGLE_PRE = frozenset({"a", "b", "c", "m"})
_TOKEN = re.compile(r"\d+|[a-z]+")
_EPOCH = re.compile(r"^(\d+):(.+)$")
_NOT_A_VERSION = frozenset({"", "*", "-", "n/a", "na", "unknown", "latest", "any"})

# (category, number-or-rank, text). Categories: -1 pre-release < 0 end < 1 post/other suffix < 2 number.
_Tok = tuple[int, int, str]


def parse_version(value: object) -> tuple[int, list[_Tok]] | None:
    """Tokenize a version string; ``None`` when it does not look like a version (must start with a digit)."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in _NOT_A_VERSION or len(s) > 128:
        return None
    epoch = 0
    m = _EPOCH.match(s)
    if m:
        epoch, s = int(m.group(1)), m.group(2)
    if s.startswith("v") and len(s) > 1 and s[1].isdigit():
        s = s[1:]
    if not s[:1].isdigit():
        return None
    raw = _TOKEN.findall(s)
    tokens: list[_Tok] = []
    for i, t in enumerate(raw):
        if t.isdigit():
            tokens.append((2, int(t), ""))
            continue
        next_is_number = i + 1 < len(raw) and raw[i + 1].isdigit()
        if t in _ALWAYS_PRE or (t in _SINGLE_PRE and next_is_number):
            tokens.append((-1, _PRE_RANK[t], ""))
        else:
            tokens.append((1, 0, t))
    return epoch, tokens


def _pad(other: _Tok) -> _Tok:
    # Missing trailing parts compare as 0 against numbers ("1.0" == "1.0.0") and as "end" against suffixes.
    return (2, 0, "") if other[0] == 2 else (0, 0, "")


def compare_versions(a: object, b: object) -> int | None:
    """-1/0/1 like ``cmp``; ``None`` when either side cannot be parsed."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    if pa[0] != pb[0]:
        return -1 if pa[0] < pb[0] else 1
    ta, tb = pa[1], pb[1]
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x is None:
            assert y is not None
            x = _pad(y)
        if y is None:
            y = _pad(x)
        if x != y:
            return -1 if x < y else 1
    return 0


def _norm_version_text(v: str) -> str:
    return v.strip().lower().removeprefix("v")


@dataclass(frozen=True)
class Bound:
    version: str
    inclusive: bool


@dataclass
class Interval:
    lower: Bound | None = None
    upper: Bound | None = None

    def contains(self, v: str) -> bool | None:
        if self.lower is not None:
            c = compare_versions(v, self.lower.version)
            if c is None:
                return None
            if c < 0 or (c == 0 and not self.lower.inclusive):
                return False
        if self.upper is not None:
            c = compare_versions(v, self.upper.version)
            if c is None:
                return None
            if c > 0 or (c == 0 and not self.upper.inclusive):
                return False
        return True

    def describe(self) -> str:
        parts = []
        if self.lower is not None:
            parts.append(f"{'>=' if self.lower.inclusive else '>'}{self.lower.version}")
        if self.upper is not None:
            parts.append(f"{'<=' if self.upper.inclusive else '<'}{self.upper.version}")
        return ",".join(parts) or "any"


@dataclass
class VersionSpec:
    intervals: list[Interval] = field(default_factory=list)
    exact: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    all_versions: bool = False
    unparsed: list[str] = field(default_factory=list)

    def describe(self) -> str:
        if self.all_versions:
            return "all versions"
        items = [i.describe() for i in self.intervals] + [f"={e}" for e in self.exact] + self.patterns
        items += [f"'{u}'" for u in self.unparsed]
        return " | ".join(items) or "unspecified"

    def evaluate(self, version: str) -> tuple[bool | None, str]:
        """(verdict, how). verdict None = could not decide (comparison failed)."""
        if self.all_versions:
            return True, "all"
        unknown = bool(self.unparsed)
        for e in self.exact:
            c = compare_versions(version, e)
            if c is None:
                if _norm_version_text(version) == _norm_version_text(e):
                    return True, "exact"
                unknown = True
            elif c == 0:
                return True, "exact"
        for p in self.patterns:
            if fnmatch.fnmatchcase(_norm_version_text(version), p.lower()):
                return True, "range"
        for iv in self.intervals:
            r = iv.contains(version)
            if r:
                return True, "range"
            if r is None:
                unknown = True
        return (None, "unknown") if unknown else (False, "outside")


_RANGE_KEYS: dict[str, tuple[str, ...]] = {
    "start_incl": ("versionStartIncluding", "version_start_including", "start_including"),
    "start_excl": ("versionStartExcluding", "version_start_excluding", "start_excluding"),
    "end_incl": ("versionEndIncluding", "version_end_including", "end_including"),
    "end_excl": ("versionEndExcluding", "version_end_excluding", "end_excluding"),
}
_CONSTRAINT = re.compile(r"(<=|>=|==|<|>|=)\s*([^\s,<>=|]+)")


def _first(d: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v)
    return None


def _interval_from_nvd(d: Mapping[str, Any]) -> Interval | None:
    si, se = _first(d, _RANGE_KEYS["start_incl"]), _first(d, _RANGE_KEYS["start_excl"])
    ei, ee = _first(d, _RANGE_KEYS["end_incl"]), _first(d, _RANGE_KEYS["end_excl"])
    if not any((si, se, ei, ee)):
        return None
    lower = Bound(si, True) if si else (Bound(se, False) if se else None)
    upper = Bound(ei, True) if ei else (Bound(ee, False) if ee else None)
    return Interval(lower, upper)


def _intervals_from_osv_events(events: Sequence[Mapping[str, Any]]) -> list[Interval]:
    out: list[Interval] = []
    current: Interval | None = None
    for ev in events:
        if not isinstance(ev, Mapping):
            continue
        if "introduced" in ev:
            intro = str(ev["introduced"])
            current = Interval(lower=None if intro in ("0", "") else Bound(intro, True))
        elif current is not None and ("fixed" in ev or "limit" in ev):
            current.upper = Bound(str(ev.get("fixed") or ev.get("limit")), False)
            out.append(current)
            current = None
        elif current is not None and "last_affected" in ev:
            current.upper = Bound(str(ev["last_affected"]), True)
            out.append(current)
            current = None
    if current is not None:
        out.append(current)  # introduced without a fix: still affected
    return out


def _parse_constraints(expr: str) -> list[Interval] | None:
    intervals: list[Interval] = []
    for alt in expr.split("||"):
        parts = _CONSTRAINT.findall(alt)
        leftover = _CONSTRAINT.sub("", alt).replace(",", " ").strip()
        if not parts or leftover:
            return None
        iv = Interval()
        for op, ver in parts:
            if op in ("<", "<="):
                iv.upper = Bound(ver, op == "<=")
            elif op in (">", ">="):
                iv.lower = Bound(ver, op == ">=")
            else:
                iv.lower = iv.upper = Bound(ver, True)
        intervals.append(iv)
    return intervals


def version_spec(affected: Mapping[str, Any], cpe: Cpe | None = None) -> VersionSpec:
    """Build the affected-version specification of one ``affected`` entry."""
    spec = VersionSpec()
    nvd = _interval_from_nvd(affected)
    if nvd is not None:
        spec.intervals.append(nvd)
    if any(k in affected for k in ("introduced", "fixed", "last_affected")):
        events: list[dict[str, Any]] = [{"introduced": affected.get("introduced") or "0"}]
        if affected.get("fixed"):
            events.append({"fixed": affected["fixed"]})
        elif affected.get("last_affected"):
            events.append({"last_affected": affected["last_affected"]})
        spec.intervals.extend(_intervals_from_osv_events(events))
    ranges = affected.get("ranges")
    if isinstance(ranges, list):
        for r in ranges:
            if not isinstance(r, Mapping):
                continue
            if str(r.get("type", "")).upper() == "GIT":
                continue  # commit hashes cannot be compared to installed versions
            if isinstance(r.get("events"), list):
                spec.intervals.extend(_intervals_from_osv_events(r["events"]))
            else:
                iv = _interval_from_nvd(r)
                if iv is not None:
                    spec.intervals.append(iv)
    versions = affected.get("versions")
    if isinstance(versions, list):
        spec.exact.extend(str(v) for v in versions if v not in (None, ""))
    if spec.intervals or spec.exact:
        return spec

    raw = affected.get("version")
    version = str(raw).strip() if raw not in (None, "") else None
    if version is None and cpe is not None:
        version = cpe.full_version()
    if version is None or version in ("*", "-"):
        spec.all_versions = True
    elif any(ch in version for ch in "<>=") or "||" in version:
        parsed = _parse_constraints(version)
        if parsed is None:
            spec.unparsed.append(version)
        else:
            spec.intervals.extend(parsed)
    elif "*" in version or "?" in version:
        spec.patterns.append(version)
    else:
        spec.exact.append(version)
    return spec


# ---------------------------------------------------------------------------------------------------------------
# CPE + names
# ---------------------------------------------------------------------------------------------------------------

_CPE_FIELDS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
_ANY = frozenset({"*", ""})


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    def full_version(self) -> str | None:
        """Version (+update such as OpenSSH ``p1``) or None for ANY/NA."""
        if self.version in _ANY or self.version == "-":
            return None
        if self.update not in _ANY and self.update != "-":
            return f"{self.version}{self.update}"
        return self.version

    def short(self) -> str:
        return f"{self.vendor}:{self.product}"


def _split_cpe23(body: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in body:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def parse_cpe(value: object) -> Cpe | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    low = s.lower()
    if low.startswith("cpe:2.3:"):
        parts = _split_cpe23(s[8:])
    elif low.startswith("cpe:/"):
        parts = [unquote(p) for p in s[5:].split(":")]
        parts = [p or "*" for p in parts]
    else:
        return None
    if len(parts) < 3:
        return None
    parts = [p.strip().lower() or "*" for p in parts[: len(_CPE_FIELDS)]]
    parts += ["*"] * (len(_CPE_FIELDS) - len(parts))
    return Cpe(*parts)


def normalize_name(value: object) -> str:
    """Lower-case, fold punctuation/whitespace to ``_`` ("Apache HTTP-Server" -> "apache_http_server")."""
    if value is None:
        return ""
    s = str(value).replace("\\", "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


def vendor_key(vendor: object) -> str:
    tokens = [t for t in normalize_name(vendor).split("_") if t]
    while tokens and tokens[0] in _VENDOR_NOISE:
        tokens.pop(0)
    while len(tokens) > 1 and tokens[-1] in _VENDOR_NOISE:
        tokens.pop()
    key = "_".join(tokens)
    return VENDOR_ALIASES.get(key, key)


def product_key(product: object, vendor: object = None) -> str:
    p = normalize_name(product)
    if vendor:
        for v in {normalize_name(vendor), vendor_key(vendor)}:
            if v and p.startswith(v + "_") and len(p) > len(v) + 1:
                p = p[len(v) + 1 :]
                break
    return PRODUCT_ALIASES.get(p, p)


def _has_glob(s: str) -> bool:
    return "*" in s or "?" in s


@dataclass(frozen=True)
class SoftwareTarget:
    """Normalized view of a SoftwareItem-like dict (asset software or vulnerability ``affected`` entry)."""

    product: str  # product key
    product_pattern: str | None  # raw CPE glob such as "http_serv*" (vulnerability side only)
    vendor: str | None  # vendor key
    vendor_pattern: str | None
    version: str | None
    ecosystem: str | None
    cpe: Cpe | None
    display: str

    @property
    def index_key(self) -> str:
        return "*" if self.product_pattern is not None else self.product


def software_target(item: Mapping[str, Any]) -> SoftwareTarget | None:
    cpe = parse_cpe(item.get("cpe"))
    raw_vendor = item.get("vendor") or (
        cpe.vendor if cpe and cpe.vendor not in _ANY and cpe.vendor != "-" else None
    )
    raw_product = item.get("product") or (
        cpe.product if cpe and cpe.product not in _ANY and cpe.product != "-" else None
    )
    product_pattern: str | None = None
    vendor_pattern: str | None = None
    if cpe is not None and not item.get("product"):
        if cpe.product in _ANY:
            product_pattern = "*"
        elif _has_glob(cpe.product):
            product_pattern = cpe.product
    if cpe is not None and not item.get("vendor") and cpe.vendor not in _ANY and _has_glob(cpe.vendor):
        vendor_pattern = cpe.vendor
        raw_vendor = None
    if not raw_product and product_pattern is None:
        return None
    product = product_key(raw_product, raw_vendor) if raw_product and product_pattern is None else ""
    raw_version = item.get("version")
    version = str(raw_version).strip() if raw_version not in (None, "") else None
    if version is None and cpe is not None:
        version = cpe.full_version()
    eco = item.get("ecosystem")
    display = " ".join(
        str(x) for x in (raw_vendor, raw_product or (cpe.product if cpe else ""), version) if x
    )
    return SoftwareTarget(
        product=product,
        product_pattern=product_pattern,
        vendor=vendor_key(raw_vendor) if raw_vendor else None,
        vendor_pattern=vendor_pattern,
        version=version,
        ecosystem=str(eco).strip().lower() if eco else None,
        cpe=cpe,
        display=display or "?",
    )


@dataclass(frozen=True)
class SoftwareMatch:
    confidence: float
    reason: str
    method: str  # "cpe" | "name"


def _product_matches(vuln: SoftwareTarget, asset: SoftwareTarget) -> bool:
    if vuln.product_pattern is not None:
        return vuln.product_pattern == "*" or fnmatch.fnmatchcase(asset.product, vuln.product_pattern)
    return vuln.product == asset.product


def _vendor_matches(vuln: SoftwareTarget, asset: SoftwareTarget) -> bool | None:
    """True/False when both vendors are known; None when one side is unknown."""
    if asset.vendor is None:
        return None
    if vuln.vendor_pattern is not None:
        return fnmatch.fnmatchcase(asset.vendor, vuln.vendor_pattern)
    if vuln.vendor is None:
        return None
    return vuln.vendor == asset.vendor


def match_software(asset_item: Mapping[str, Any], affected: Mapping[str, Any]) -> SoftwareMatch | None:
    """Does this asset software fall into this affected entry? Returns confidence + reason, or None."""
    if affected.get("vulnerable") is False:
        return None
    a = software_target(asset_item)
    v = software_target(affected)
    if a is None or v is None or not a.product:
        return None
    if (
        a.cpe is not None
        and v.cpe is not None
        and a.cpe.part not in _ANY
        and v.cpe.part not in _ANY
        and a.cpe.part != v.cpe.part
    ):
        return None
    if a.ecosystem and v.ecosystem and a.ecosystem != v.ecosystem:
        return None
    if not _product_matches(v, a):
        return None
    vendor_ok = _vendor_matches(v, a)
    if vendor_ok is False:
        return None
    vendor_confirmed = vendor_ok is True
    eco_confirmed = bool(a.ecosystem and v.ecosystem)
    if v.product_pattern == "*" and not vendor_confirmed:
        return None  # "any product of an unknown vendor" is meaningless
    if not (vendor_confirmed or eco_confirmed) and (a.product in GENERIC_PRODUCTS or len(a.product) < 2):
        return None
    use_cpe = v.cpe is not None and vendor_confirmed

    spec = version_spec(affected, v.cpe)
    if spec.all_versions:
        base = CONF_ALL_VERSIONS_CPE if use_cpe else CONF_ALL_VERSIONS_NAME
        vdesc = "all versions affected"
    elif a.version is None:
        base, vdesc = CONF_UNKNOWN_VERSION, f"asset version unknown (affected: {spec.describe()})"
    else:
        verdict, how = spec.evaluate(a.version)
        if verdict is False:
            return None
        if verdict is None:
            base = CONF_INCONCLUSIVE
            vdesc = f"version comparison inconclusive: {a.version} vs {spec.describe()}"
        elif how == "exact":
            base, vdesc = CONF_EXACT, f"version {a.version} listed as affected"
        else:
            base, vdesc = CONF_RANGE, f"version {a.version} within {spec.describe()}"
    if not use_cpe:
        base -= PENALTY_NAME_CONFIRMED if (vendor_confirmed or eco_confirmed) else PENALTY_NAME_ONLY
    confidence = round(max(0.0, min(1.0, base)), 2)
    if confidence < MIN_CONFIDENCE:
        return None
    if use_cpe:
        assert v.cpe is not None
        head = f"CPE match {v.cpe.short()}"
    else:
        basis = "vendor" if vendor_confirmed else ("ecosystem" if eco_confirmed else "name only")
        head = f"Name match '{v.display}' ({basis})"
    return SoftwareMatch(
        confidence, f"{head} <- asset software '{a.display}'; {vdesc}", "cpe" if use_cpe else "name"
    )


@dataclass(frozen=True)
class AssetMatch:
    asset_id: str
    software: dict[str, Any]
    match: SoftwareMatch


class AssetIndex:
    """Product-key index over asset software so each vulnerability only checks plausible candidates."""

    def __init__(self, assets: Sequence[tuple[str, Sequence[Mapping[str, Any]]]]) -> None:
        self.by_key: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        self.all: list[tuple[str, dict[str, Any]]] = []
        for asset_id, software in assets:
            for sw in software or []:
                if not isinstance(sw, Mapping):
                    continue
                t = software_target(sw)
                if t is None or not t.product:
                    continue
                entry = (asset_id, dict(sw))
                self.by_key.setdefault(t.product, []).append(entry)
                self.all.append(entry)

    def candidates(self, key: str) -> list[tuple[str, dict[str, Any]]]:
        return self.all if key == "*" else self.by_key.get(key, [])

    def match_vuln(self, affected: Sequence[Mapping[str, Any]]) -> dict[str, AssetMatch]:
        best: dict[str, AssetMatch] = {}
        for entry in affected or []:
            if not isinstance(entry, Mapping):
                continue
            target = software_target(entry)
            if target is None:
                continue
            for asset_id, sw in self.candidates(target.index_key):
                try:
                    m = match_software(sw, entry)
                except Exception:
                    log.exception("matcher failed on %r vs %r", sw, entry)
                    continue
                if m is None:
                    continue
                cur = best.get(asset_id)
                if cur is None or m.confidence > cur.match.confidence:
                    best[asset_id] = AssetMatch(asset_id, sw, m)
        return best


def match_asset_to_vuln(
    software: Sequence[Mapping[str, Any]], affected: Sequence[Mapping[str, Any]]
) -> AssetMatch | None:
    """Convenience for tests / one-off checks: best match of one asset's software list against one vuln."""
    return AssetIndex([("_", software)]).match_vuln(affected).get("_")


# ---------------------------------------------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------------------------------------------


class LoopLocks:
    """asyncio locks keyed by name, recreated per event loop (tests run one loop per test)."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._locks: dict[str, asyncio.Lock] = {}

    def get(self, key: str = "") -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if loop is not self._loop:
            self._loop, self._locks = loop, {}
        if len(self._locks) > 2000:
            self._locks = {k: v for k, v in self._locks.items() if v.locked()}
        lock = self._locks.get(key)
        if lock is None:
            lock = self._locks[key] = asyncio.Lock()
        return lock


_locks = LoopLocks()


@dataclass
class MatchSummary:
    evaluated_vulns: int = 0
    matched: int = 0
    created: list[VulnMatch] = field(default_factory=list)
    updated: int = 0
    closed: int = 0
    reopened: int = 0


async def run_matching(
    *,
    asset_ids: Sequence[str] | None = None,
    vuln_ids: Sequence[str] | None = None,
    publish: bool = True,
) -> MatchSummary:
    """Match (a subset of) assets against (a subset of) vulns and upsert ``vuln_matches``.

    - new matches -> inserted as ``open`` and published as ``intel.vuln_matched`` (after commit);
    - existing matches -> reason/confidence refreshed; analyst decisions (mitigated/accepted/false_positive)
      are never overwritten, except that a match TOKIWA auto-closed itself is reopened when it matches again;
    - open matches in scope that no longer match (asset patched, feed corrected) -> auto-closed as ``mitigated``.
    """
    summary = MatchSummary()
    asset_scope = list(dict.fromkeys(asset_ids)) if asset_ids is not None else None
    vuln_scope = list(dict.fromkeys(vuln_ids)) if vuln_ids is not None else None
    if (asset_scope is not None and not asset_scope) or (vuln_scope is not None and not vuln_scope):
        return summary
    async with _locks.get("run_matching"), session_scope() as session:
        stmt = select(AssetRow.id, AssetRow.software)
        if asset_scope is not None:
            stmt = stmt.where(AssetRow.id.in_(asset_scope))
        assets = [(r[0], r[1] or []) for r in (await session.execute(stmt)).all()]
        existing_assets = {a for a, _ in assets}
        index = AssetIndex(assets)

        found: dict[tuple[str, str], AssetMatch] = {}
        if index.all:
            last_id = ""
            while True:
                vstmt = select(VulnRow.id, VulnRow.affected).where(VulnRow.id > last_id)
                if vuln_scope is not None:
                    vstmt = vstmt.where(VulnRow.id.in_(vuln_scope))
                rows = (await session.execute(vstmt.order_by(VulnRow.id).limit(500))).all()
                if not rows:
                    break
                for vid, affected in rows:
                    summary.evaluated_vulns += 1
                    if not affected:
                        continue
                    for asset_id, m in index.match_vuln(affected).items():
                        found[(vid, asset_id)] = m
                last_id = rows[-1][0]
        summary.matched = len(found)

        mstmt = select(VulnMatchRow)
        if asset_scope is not None:
            mstmt = mstmt.where(VulnMatchRow.asset_id.in_(asset_scope))
        if vuln_scope is not None:
            mstmt = mstmt.where(VulnMatchRow.vuln_id.in_(vuln_scope))
        existing: dict[tuple[str, str], VulnMatchRow] = {}
        for row in (await session.execute(mstmt.order_by(VulnMatchRow.created_at))).scalars():
            key = (row.vuln_id, row.asset_id)
            if key in existing:
                await session.delete(row)  # duplicate from an older race; keep the first
                continue
            existing[key] = row

        new_rows: list[VulnMatchRow] = []
        for key, m in found.items():
            cur = existing.get(key)
            if cur is None:
                cur = VulnMatchRow(
                    id=new_id(),
                    vuln_id=key[0],
                    asset_id=key[1],
                    software=m.software,
                    reason=m.match.reason,
                    confidence=m.match.confidence,
                    status=MatchStatus.OPEN.value,
                    created_at=utcnow(),
                )
                session.add(cur)
                new_rows.append(cur)
                continue
            if cur.status == MatchStatus.MITIGATED and cur.reason.startswith(AUTO_CLOSED_PREFIX):
                cur.status = MatchStatus.OPEN.value  # TOKIWA closed it itself; it matches again -> reopen
                summary.reopened += 1
                new_rows.append(cur)
            if (cur.reason, cur.confidence, cur.software) != (m.match.reason, m.match.confidence, m.software):
                cur.reason, cur.confidence, cur.software = m.match.reason, m.match.confidence, m.software
                summary.updated += 1

        for key, row in existing.items():
            if key in found:
                continue
            if key[1] not in existing_assets and asset_scope is None:
                await session.delete(row)  # the asset no longer exists
                continue
            if row.status == MatchStatus.OPEN:
                note = "no longer matches current asset software / vulnerability data"
                row.status = MatchStatus.MITIGATED.value
                row.reason = f"{AUTO_CLOSED_PREFIX}{note} (was: {row.reason})"[:4000]
                summary.closed += 1
        await session.flush()
        summary.created = [VulnMatch.model_validate(r) for r in new_rows]
    if publish:
        for vm in summary.created:
            await bus.publish("intel.vuln_matched", vm)
    if summary.created or summary.closed:
        log.info(
            "intel matcher: %d vulns evaluated, %d matches (%d new, %d updated, %d closed)",
            summary.evaluated_vulns,
            summary.matched,
            len(summary.created),
            summary.updated,
            summary.closed,
        )
    return summary


async def delete_matches_for_asset(session: AsyncSession, asset_id: str) -> None:
    await session.execute(delete(VulnMatchRow).where(VulnMatchRow.asset_id == asset_id))


async def open_exposures(
    session: AsyncSession,
    asset_ids: Iterable[str],
    *,
    epss_threshold: float,
    min_confidence: float = 0.5,
) -> dict[str, list[dict[str, Any]]]:
    """Open matches of the given assets whose vuln is in CISA KEV or has EPSS >= threshold."""
    ids = [a for a in dict.fromkeys(asset_ids) if a]
    if not ids:
        return {}
    stmt = (
        select(VulnMatchRow, VulnRow.kev, VulnRow.epss, VulnRow.title, VulnRow.cvss_score)
        .join(VulnRow, VulnRow.id == VulnMatchRow.vuln_id)
        .where(
            VulnMatchRow.asset_id.in_(ids),
            VulnMatchRow.status == MatchStatus.OPEN.value,
            VulnMatchRow.confidence >= min_confidence,
            or_(VulnRow.kev.is_(True), VulnRow.epss >= epss_threshold),
        )
    )
    out: dict[str, list[dict[str, Any]]] = {}
    for row, kev, epss, title, cvss in (await session.execute(stmt)).all():
        out.setdefault(row.asset_id, []).append(
            {
                "vuln_id": row.vuln_id,
                "kev": bool(kev),
                "epss": epss,
                "cvss_score": cvss,
                "title": title,
                "match_id": row.id,
                "match_confidence": row.confidence,
                "reason": row.reason,
            }
        )
    for items in out.values():
        items.sort(key=lambda x: (not x["kev"], -(x["epss"] or 0.0), x["vuln_id"]))
    return out


def software_terms(software: Iterable[Mapping[str, Any]]) -> set[str]:
    """Distinctive normalized product terms of an asset (used to judge free-text relevance, e.g. research)."""
    terms: set[str] = set()
    for sw in software or []:
        if not isinstance(sw, Mapping):
            continue
        t = software_target(sw)
        if t is None:
            continue
        for term in (t.product, normalize_name(sw.get("product"))):
            if term and len(term) >= 3 and term not in GENERIC_PRODUCTS:
                terms.add(term)
    return terms


def text_mentions(text: str, terms: Iterable[str]) -> bool:
    hay = f"_{normalize_name(text)}_"
    return any(f"_{t}_" in hay for t in terms)


def extract_vuln_ids(payload: Any) -> list[str]:
    """Vuln ids from an ``intel.vuln_updated`` payload. The publisher (intel-feeds) may send a VulnRecord, a dict
    (``id`` / ``vuln_id`` / ``vuln_ids`` / ``ids``), a plain id or a list of any of these."""
    out: list[str] = []

    def visit(p: Any, depth: int = 0) -> None:
        if depth > 3 or p is None:
            return
        if isinstance(p, str):
            if p.strip():
                out.append(p.strip())
        elif isinstance(p, BaseModel):
            visit(p.model_dump(), depth + 1)
        elif isinstance(p, Mapping):
            for k in ("vuln_ids", "ids"):
                if isinstance(p.get(k), list | tuple):
                    visit(list(p[k]), depth + 1)
            for k in ("id", "vuln_id"):
                if isinstance(p.get(k), str):
                    visit(p[k], depth + 1)
        elif isinstance(p, list | tuple | set):
            for item in p:
                visit(item, depth + 1)

    visit(payload)
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------------------------------------------------------
# Triggers: intel.vuln_updated (bus), periodic full pass. Asset create/update triggers live in routes/assets.py.
# ---------------------------------------------------------------------------------------------------------------


async def _on_vuln_updated(payload: Any) -> None:
    ids = extract_vuln_ids(payload)
    if not ids:
        return
    await run_matching(vuln_ids=ids)
    from tokiwa.intel.advisor import advise_for_vulns  # late import: advisor imports this module

    await advise_for_vulns(ids)


@on_startup
async def _subscribe_matcher() -> None:
    bus.subscribe("intel.vuln_updated", _on_vuln_updated)


@periodic(
    "intel.match",
    every_seconds=lambda s: max(15, s.intel.sync_interval_minutes) * 60,
    initial_delay=120,
    enabled=lambda s: s.intel.enabled,
)
async def match_all_job() -> None:
    await run_matching()
