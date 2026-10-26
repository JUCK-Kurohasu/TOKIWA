"""Index of active deception assets and the pure event matcher.

Used by the ``deception.trip`` detector (alerts) and by the trip recorder in :mod:`tokiwa.deception.service`
(trip counters, ``deception.tripped``). Pure functions only - the DB-backed cache lives in the service.

What counts as a trip
---------------------
* any known token / derived credential value found in path, query, headers, body, referrer, UA, message,
  LLM-app prompt, command line or the raw record (substring match, URL-decoded too);
* a request for a decoy path (normalized: decoded, ``//`` and ``..`` collapsed, case-insensitive);
* a request below a labyrinth prefix (or a wildcard decoy);
* a Gate ``kind=deception`` event naming a non-canary asset.

Fetching an AI-canary *page* (robots.txt, OpenAPI ...) is NOT a trip - legitimate crawlers read robots.txt.
Only using the canary value is.

AI canary "followed" (= LLM agent, ai_score 0.99): the canary value is sent in the configured header
(``deception.canary_header``), or the path / referrer starts with ``/api/internal/<value>`` - the composition the
instruction asks for. A canary value seen anywhere else is "observed" (strong, but a human could have copied it).
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import unquote, unquote_plus

from tokiwa.config import DeceptionSettings
from tokiwa.deception import labyrinth
from tokiwa.deception.templates import CANARY_PATH_PREFIX
from tokiwa.deception.tokens import MIN_TOKEN_LEN, Slot, honey_values
from tokiwa.schemas.events import Event
from tokiwa.schemas.response import DeceptionAsset, DeceptionKind

_RAW_SCAN_LIMIT = 16_384


class TripType(StrEnum):
    AI_CANARY_FOLLOWED = "ai_canary_followed"
    AI_CANARY_TOKEN = "ai_canary_token"
    HONEYTOKEN = "honeytoken"
    DECOY_PATH = "decoy_path"
    LABYRINTH = "labyrinth"


# strongest first: one trip per (event, asset) keeps the strongest classification
_PRIORITY = [
    TripType.AI_CANARY_FOLLOWED,
    TripType.AI_CANARY_TOKEN,
    TripType.HONEYTOKEN,
    TripType.DECOY_PATH,
    TripType.LABYRINTH,
]


@dataclass(frozen=True, slots=True)
class IndexedAsset:
    id: str
    kind: DeceptionKind
    name: str
    path: str | None
    token: str | None

    @classmethod
    def of(cls, a: DeceptionAsset) -> IndexedAsset:
        return cls(id=a.id, kind=DeceptionKind(a.kind), name=a.name, path=a.path, token=a.token)


@dataclass(frozen=True, slots=True)
class TokenRef:
    asset: IndexedAsset
    slot: Slot
    value: str


@dataclass(frozen=True, slots=True)
class TokenMatch:
    slot: Slot
    field: str
    value: str


@dataclass
class Trip:
    asset: IndexedAsset
    trip_type: TripType
    matches: list[TokenMatch] = field(default_factory=list)
    path_hit: bool = False
    depth: int | None = None

    @property
    def ai_followed(self) -> bool:
        return self.trip_type == TripType.AI_CANARY_FOLLOWED

    @property
    def token(self) -> str | None:
        for m in self.matches:
            if m.slot == Slot.CANARY:
                return m.value
        return self.matches[0].value if self.matches else None

    @property
    def fields(self) -> list[str]:
        return sorted({m.field for m in self.matches})

    @property
    def slots(self) -> list[str]:
        return sorted({m.slot.value for m in self.matches})


def normalize_path(path: str | None) -> str:
    """Canonical, lower-cased request path used for decoy matching (defeats ``//.env``, ``/a/../.env``, ``%2e``)."""
    p = path or "/"
    for _ in range(2):  # double-encoding
        if "%" not in p:
            break
        p = unquote(p)
    p = p.replace("\\", "/").split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    trailing = p.endswith("/") and p != "/"
    p = re.sub(r"/{2,}", "/", p)
    p = posixpath.normpath(p)
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    if trailing and p != "/":
        p += "/"
    return p.lower()


def _exact_key(path: str) -> str:
    p = normalize_path(path)
    return p.rstrip("/") or "/"


class DeceptionIndex:
    """Immutable lookup structure built from the enabled assets."""

    def __init__(
        self,
        tokens: dict[str, TokenRef],
        exact_paths: dict[str, IndexedAsset],
        prefixes: list[tuple[str, IndexedAsset]],
        assets: dict[str, IndexedAsset],
        canary_header: str,
    ) -> None:
        self.tokens = tokens
        self.exact_paths = exact_paths
        self.prefixes = sorted(prefixes, key=lambda p: len(p[0]), reverse=True)
        self.assets = assets
        self.canary_header = canary_header.lower()
        values = sorted((v for v in tokens if len(v) >= MIN_TOKEN_LEN), key=len, reverse=True)
        self._pattern = re.compile("|".join(re.escape(v) for v in values)) if values else None

    @property
    def empty(self) -> bool:
        return not self.assets

    @classmethod
    def empty_index(cls, canary_header: str = "x-debug-auth") -> DeceptionIndex:
        return cls({}, {}, [], {}, canary_header)

    @classmethod
    def build(
        cls, assets: Iterable[DeceptionAsset], *, key: bytes, settings: DeceptionSettings
    ) -> DeceptionIndex:
        tokens: dict[str, TokenRef] = {}
        exact: dict[str, IndexedAsset] = {}
        prefixes: list[tuple[str, IndexedAsset]] = []
        by_id: dict[str, IndexedAsset] = {}
        if not settings.enabled:
            return cls.empty_index(settings.canary_header)
        for a in assets:
            if not a.enabled:
                continue
            ia = IndexedAsset.of(a)
            if ia.kind == DeceptionKind.LABYRINTH and not settings.labyrinth_enabled:
                continue
            by_id[ia.id] = ia
            if ia.token:
                for slot, value in honey_values(ia.kind, ia.token, key).items():
                    tokens.setdefault(value, TokenRef(ia, slot, value))
            if ia.kind == DeceptionKind.AI_CANARY:
                continue  # fetching a canary page is not a trip; only using the value is
            if ia.kind == DeceptionKind.LABYRINTH:
                base = labyrinth.normalize_base(ia.path, settings.labyrinth_prefix)
                prefixes.append((normalize_path(base), ia))
                continue
            if ia.path:
                if ia.path.endswith("*"):
                    prefixes.append((normalize_path(ia.path[:-1] or "/"), ia))
                else:
                    exact.setdefault(_exact_key(ia.path), ia)
        return cls(tokens, exact, prefixes, by_id, settings.canary_header)

    def find_tokens(self, text: str) -> list[str]:
        if self._pattern is None or not text:
            return []
        return [m.group(0) for m in self._pattern.finditer(text)]

    def match_path(self, path: str) -> tuple[IndexedAsset | None, int | None]:
        norm = normalize_path(path)
        key = norm.rstrip("/") or "/"
        hit = self.exact_paths.get(key)
        if hit is not None:
            return hit, None
        for prefix, asset in self.prefixes:
            root = prefix.rstrip("/") or "/"
            if norm.startswith(prefix) or key == root:
                depth = labyrinth.depth_of(prefix, norm) if asset.kind == DeceptionKind.LABYRINTH else None
                return asset, depth
        return None, None


def iter_fields(event: Event) -> Iterator[tuple[str, str]]:
    """(field name, text) pairs that may carry a token. Header names are lower-cased by the schema."""
    h = event.http
    if h is not None:
        for name, value in (
            ("http.path", h.path),
            ("http.query", h.query),
            ("http.request_body", h.request_body),
            ("http.referrer", h.referrer),
            ("http.user_agent", h.user_agent),
            ("http.host", h.host),
        ):
            if value:
                yield name, value
        for k, v in h.headers.items():
            if v:
                yield f"http.headers.{k.lower()}", v
    if event.llm_app is not None and event.llm_app.prompt:
        yield "llm_app.prompt", event.llm_app.prompt
    if event.message:
        yield "message", event.message
    if event.process is not None and event.process.cmdline:
        yield "process.cmdline", event.process.cmdline
    if event.network is not None and event.network.process is not None and event.network.process.cmdline:
        yield "network.process.cmdline", event.network.process.cmdline
    if event.deception is not None and event.deception.token:
        yield "deception.token", event.deception.token
    if event.raw:
        try:
            raw = json.dumps(event.raw, ensure_ascii=False, default=str)[:_RAW_SCAN_LIMIT]
        except (TypeError, ValueError):
            raw = ""
        if raw:
            yield "raw", raw


def _variants(text: str) -> list[str]:
    out = [text]
    if "%" in text or "+" in text:
        decoded = unquote_plus(text)
        if decoded != text:
            out.append(decoded)
    return out


@dataclass
class _Acc:
    asset: IndexedAsset
    matches: list[TokenMatch] = field(default_factory=list)
    path_hit: bool = False
    depth: int | None = None


def _followed(m: TokenMatch, event: Event, index: DeceptionIndex) -> bool:
    if m.slot != Slot.CANARY:
        return False
    if m.field == f"http.headers.{index.canary_header}":
        return True
    composed = f"{CANARY_PATH_PREFIX}{m.value}".lower()
    if m.field == "http.path" and event.http is not None:
        return normalize_path(event.http.path).startswith(composed)
    if m.field in ("http.referrer", "http.headers.referer"):
        text: str | None = None
        if event.http is not None:
            text = event.http.referrer if m.field == "http.referrer" else event.http.headers.get("referer")
        return composed in unquote(text or "").lower()
    return False


def _classify(acc: _Acc, event: Event, index: DeceptionIndex) -> Trip | None:
    kinds: set[TripType] = set()
    for m in acc.matches:
        if m.slot == Slot.CANARY:
            kinds.add(TripType.AI_CANARY_FOLLOWED if _followed(m, event, index) else TripType.AI_CANARY_TOKEN)
        else:
            kinds.add(TripType.HONEYTOKEN)
    if acc.path_hit:
        kinds.add(TripType.LABYRINTH if acc.asset.kind == DeceptionKind.LABYRINTH else TripType.DECOY_PATH)
    for t in _PRIORITY:
        if t in kinds:
            return Trip(acc.asset, t, acc.matches, acc.path_hit, acc.depth)
    return None


def match_event(event: Event, index: DeceptionIndex) -> list[Trip]:
    """All trips in one event (at most one per asset, strongest classification). Never raises on odd input."""
    if index.empty:
        return []
    accs: dict[str, _Acc] = {}
    seen: set[tuple[str, str]] = set()
    for fname, text in iter_fields(event):
        for variant in _variants(text):
            for value in index.find_tokens(variant):
                if (fname, value) in seen:
                    continue
                seen.add((fname, value))
                ref = index.tokens.get(value)
                if ref is None:
                    continue
                acc = accs.setdefault(ref.asset.id, _Acc(ref.asset))
                acc.matches.append(TokenMatch(ref.slot, fname, value))
    if event.http is not None and event.http.path:
        asset, depth = index.match_path(event.http.path)
        if asset is not None:
            acc = accs.setdefault(asset.id, _Acc(asset))
            acc.path_hit = True
            acc.depth = depth
    if event.deception is not None and event.deception.asset_id:
        asset = index.assets.get(event.deception.asset_id)
        if asset is not None and asset.kind != DeceptionKind.AI_CANARY:
            acc = accs.setdefault(asset.id, _Acc(asset))
            acc.path_hit = True
            if acc.depth is None and asset.kind == DeceptionKind.LABYRINTH and event.http is not None:
                for prefix, a in index.prefixes:
                    if a.id == asset.id:
                        acc.depth = labyrinth.depth_of(prefix, normalize_path(event.http.path))
    trips = [_classify(acc, event, index) for acc in accs.values()]
    return [t for t in trips if t is not None]
