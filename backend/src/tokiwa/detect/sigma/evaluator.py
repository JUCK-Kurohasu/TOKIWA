"""In-memory evaluation of compiled Sigma rules against a single :class:`Event`.

The parser (``parser.py``) turns YAML into the objects defined here; everything in this module is pure and
side-effect free so it can run inside the detection engine's hot loop.

Matching semantics (Sigma specification defaults):

* string comparison is case-insensitive unless ``|cased`` (or ``|re`` without ``|i``);
* ``*`` / ``?`` are wildcards, ``\\*`` ``\\?`` ``\\\\`` escape them; any other backslash is literal;
* plain values must match the whole field (``contains``/``startswith``/``endswith`` add implicit ``*``);
* a list of values is OR, unless ``|all``; a field holding a list matches if any element matches;
* ``|re`` uses Python ``re.search`` (unanchored; use ``^``/``$`` explicitly).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from tokiwa.detect.sigma.fieldmap import Resolver, keyword_corpus, stringify
from tokiwa.schemas.events import Event, EventKind

# Long fields are truncated before matching: bounds the cost of user-supplied regexes.
MAX_MATCH_CHARS = 65_536


# ---------------------------------------------------------------------------------------------------------
# string patterns


class _Wild:
    """Wildcard token: ``*`` (many) / ``?`` (one) / a character class (windash expansion)."""

    __slots__ = ("regex",)

    def __init__(self, regex: str) -> None:
        self.regex = regex

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_Wild({self.regex!r})"


STAR = _Wild(".*")
QMARK = _Wild(".")
Token = str | _Wild


def parse_wildcards(value: str) -> list[Token]:
    """Split a Sigma string into literal chunks and wildcard tokens (handles ``\\`` escapes)."""
    tokens: list[Token] = []
    buf: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c == "\\" and i + 1 < n and value[i + 1] in "*?\\":
            buf.append(value[i + 1])
            i += 2
            continue
        if c in "*?":
            if buf:
                tokens.append("".join(buf))
                buf = []
            tokens.append(STAR if c == "*" else QMARK)
        else:
            buf.append(c)
        i += 1
    if buf:
        tokens.append("".join(buf))
    return tokens


def has_wildcards(tokens: Sequence[Token]) -> bool:
    return any(isinstance(t, _Wild) for t in tokens)


def _merge(tokens: Sequence[Token]) -> list[Token]:
    out: list[Token] = []
    for t in tokens:
        if isinstance(t, str):
            if not t:
                continue
            if out and isinstance(out[-1], str):
                out[-1] = out[-1] + t
                continue
        elif t is STAR and out and out[-1] is STAR:
            continue
        out.append(t)
    return out


_WINDASH_RE = re.compile(r"\B[-/]\b")
WINDASH_CLASS = _Wild("[-/–—―]")


def apply_windash(tokens: Sequence[Token]) -> list[Token]:
    """``-foo`` / ``/foo`` -> any Windows option prefix (``-``, ``/``, en/em dash, horizontal bar)."""
    out: list[Token] = []
    for t in tokens:
        if not isinstance(t, str):
            out.append(t)
            continue
        last = 0
        for m in _WINDASH_RE.finditer(t):
            out.append(t[last : m.start()])
            out.append(WINDASH_CLASS)
            last = m.end()
        out.append(t[last:])
    return _merge(out)


StrPredicate = Callable[[str, str], bool]  # (original, lower-cased) -> bool


def compile_tokens(tokens: Sequence[Token], *, cased: bool = False) -> StrPredicate:
    """Compile a token sequence to a fast predicate (literal fast paths, regex otherwise)."""
    toks = _merge(tokens)
    if not toks:
        return lambda s, low: s == ""
    lits = [t for t in toks if isinstance(t, str)]
    if len(lits) == len(toks) == 1:
        lit = lits[0] if cased else lits[0].lower()
        return (lambda s, low: s == lit) if cased else (lambda s, low: low == lit)
    if len(toks) == 3 and toks[0] is STAR and toks[2] is STAR and isinstance(toks[1], str):
        lit = toks[1] if cased else toks[1].lower()
        return (lambda s, low: lit in s) if cased else (lambda s, low: lit in low)
    if len(toks) == 2 and isinstance(toks[0], str) and toks[1] is STAR:
        lit = toks[0] if cased else toks[0].lower()
        return (lambda s, low: s.startswith(lit)) if cased else (lambda s, low: low.startswith(lit))
    if len(toks) == 2 and toks[0] is STAR and isinstance(toks[1], str):
        lit = toks[1] if cased else toks[1].lower()
        return (lambda s, low: s.endswith(lit)) if cased else (lambda s, low: low.endswith(lit))
    pattern = "".join(re.escape(t) if isinstance(t, str) else t.regex for t in toks)
    flags = re.DOTALL | (0 if cased else re.IGNORECASE)
    rx = re.compile(pattern, flags)
    return lambda s, low: rx.fullmatch(s) is not None


# ---------------------------------------------------------------------------------------------------------
# value predicates: (values, present) -> bool


@dataclass(frozen=True)
class Candidate:
    raw: Any
    text: str
    lower: str


ValuePredicate = Callable[[Sequence[Candidate], bool], bool]


def string_predicate(pred: StrPredicate) -> ValuePredicate:
    def test(values: Sequence[Candidate], present: bool) -> bool:
        return any(pred(c.text, c.lower) for c in values)

    return test


def regex_predicate(rx: re.Pattern[str]) -> ValuePredicate:
    def test(values: Sequence[Candidate], present: bool) -> bool:
        return any(rx.search(c.text) is not None for c in values)

    return test


def cidr_predicate(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> ValuePredicate:
    def test(values: Sequence[Candidate], present: bool) -> bool:
        for c in values:
            text = c.text.strip().strip("[]")
            try:
                addr = ipaddress.ip_address(text)
            except ValueError:
                continue
            if addr.version == network.version and addr in network:
                return True
        return False

    return test


_NUM_OPS: dict[str, Callable[[float, float], bool]] = {
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
}


def numeric_predicate(op: str, bound: float) -> ValuePredicate:
    fn = _NUM_OPS[op]

    def test(values: Sequence[Candidate], present: bool) -> bool:
        for c in values:
            if isinstance(c.raw, bool):
                continue
            try:
                num = float(c.raw) if isinstance(c.raw, int | float) else float(c.text.strip())
            except ValueError:
                continue
            if fn(num, bound):
                return True
        return False

    return test


def exists_predicate(expected: bool) -> ValuePredicate:
    return lambda values, present: present is expected


def null_predicate() -> ValuePredicate:
    return lambda values, present: not present


# ---------------------------------------------------------------------------------------------------------
# selections


def _candidates(raw: Any) -> tuple[list[Candidate], bool]:
    if raw is None:
        return [], False
    items = raw if isinstance(raw, list | tuple | set) else [raw]
    out: list[Candidate] = []
    for item in items:
        if item is None:
            continue
        text = stringify(item)
        if len(text) > MAX_MATCH_CHARS:
            text = text[:MAX_MATCH_CHARS]
        out.append(Candidate(item, text, text.lower()))
    present = bool(out) and not (len(out) == 1 and out[0].text == "")
    return out, present


@dataclass(frozen=True)
class FieldCondition:
    """``field|modifiers: values`` - one key of a selection map."""

    field: str
    resolver: Resolver
    predicates: tuple[ValuePredicate, ...]
    require_all: bool = False

    def test(self, event: Event) -> bool:
        values, present = _candidates(self.resolver(event))
        if self.require_all:
            return all(p(values, present) for p in self.predicates)
        return any(p(values, present) for p in self.predicates)


@dataclass(frozen=True)
class KeywordCondition:
    """Keyword (full-text) search: implicit ``contains`` over :func:`keyword_corpus`."""

    predicates: tuple[StrPredicate, ...]
    require_all: bool = False

    def test(self, event: Event) -> bool:
        corpus = [(s, s.lower()) for s in keyword_corpus(event)]
        if not corpus:
            return False

        def hit(p: StrPredicate) -> bool:
            return any(p(s, low) for s, low in corpus)

        if self.require_all:
            return all(hit(p) for p in self.predicates)
        return any(hit(p) for p in self.predicates)


Condition = FieldCondition | KeywordCondition


@dataclass(frozen=True)
class Selection:
    """A named search identifier: OR over alternatives, each alternative an AND of conditions."""

    name: str
    alternatives: tuple[tuple[Condition, ...], ...]

    def test(self, event: Event) -> bool:
        return any(all(c.test(event) for c in alt) for alt in self.alternatives)


# ---------------------------------------------------------------------------------------------------------
# condition AST

SelectionEval = Callable[[str], bool]


class Node:
    def evaluate(self, sel: SelectionEval) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def identifiers(self) -> set[str]:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True)
class Ref(Node):
    name: str

    def evaluate(self, sel: SelectionEval) -> bool:
        return sel(self.name)

    def identifiers(self) -> set[str]:
        return {self.name}


@dataclass(frozen=True)
class Not(Node):
    child: Node

    def evaluate(self, sel: SelectionEval) -> bool:
        return not self.child.evaluate(sel)

    def identifiers(self) -> set[str]:
        return self.child.identifiers()


@dataclass(frozen=True)
class And(Node):
    children: tuple[Node, ...]

    def evaluate(self, sel: SelectionEval) -> bool:
        return all(c.evaluate(sel) for c in self.children)

    def identifiers(self) -> set[str]:
        return set().union(*(c.identifiers() for c in self.children))


@dataclass(frozen=True)
class Or(Node):
    children: tuple[Node, ...]

    def evaluate(self, sel: SelectionEval) -> bool:
        return any(c.evaluate(sel) for c in self.children)

    def identifiers(self) -> set[str]:
        return set().union(*(c.identifiers() for c in self.children))


@dataclass(frozen=True)
class Quantifier(Node):
    """``N of pattern`` / ``all of pattern`` (names already resolved at compile time)."""

    minimum: int  # number of names that must match
    names: tuple[str, ...]

    def evaluate(self, sel: SelectionEval) -> bool:
        hits = 0
        for n in self.names:
            if sel(n):
                hits += 1
                if hits >= self.minimum:
                    return True
        return False

    def identifiers(self) -> set[str]:
        return set(self.names)


# ---------------------------------------------------------------------------------------------------------
# compiled rule


@dataclass(frozen=True)
class MatchResult:
    matched: tuple[str, ...]  # selection names that evaluated true


@dataclass(frozen=True)
class SigmaRule:
    """A validated, compiled Sigma rule. Metadata is kept for alerting; ``raw`` is the parsed YAML."""

    title: str
    id: str | None
    status: str | None
    level: str
    description: str
    author: str | None
    tags: tuple[str, ...]
    references: tuple[str, ...]
    falsepositives: tuple[str, ...]
    logsource: dict[str, str]
    kinds: frozenset[EventKind]
    selections: dict[str, Selection]
    condition: Node
    raw: dict[str, Any] = field(repr=False, compare=False, default_factory=dict)

    def applies_to(self, kind: EventKind) -> bool:
        return kind in self.kinds

    def match(self, event: Event) -> MatchResult | None:
        """Evaluate the condition; selections are computed lazily and memoized for this event."""
        if event.kind not in self.kinds:
            return None
        memo: dict[str, bool] = {}

        def sel(name: str) -> bool:
            v = memo.get(name)
            if v is None:
                v = self.selections[name].test(event)
                memo[name] = v
            return v

        if not self.condition.evaluate(sel):
            return None
        return MatchResult(tuple(n for n, v in memo.items() if v))

    def matches(self, event: Event) -> bool:
        return self.match(event) is not None


def iter_conditions(selections: Iterable[Selection]) -> Iterable[Condition]:
    for s in selections:
        for alt in s.alternatives:
            yield from alt
