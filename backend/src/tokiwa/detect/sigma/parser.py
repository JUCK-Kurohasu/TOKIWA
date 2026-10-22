"""Sigma YAML -> validated :class:`~tokiwa.detect.sigma.evaluator.SigmaRule`.

Supported subset (see docs/detection/sigma.md):

* top level: ``title`` (required), ``id``, ``status``, ``level``, ``description``, ``author``, ``tags``,
  ``references``, ``falsepositives``, ``logsource`` (required), ``detection`` (required); other keys are kept
  in ``raw`` and ignored (Sigma allows custom attributes);
* detection: named selections (map / list of maps / keyword list), ``condition`` (string or list = OR),
  ``timeframe`` is accepted and ignored (only meaningful for aggregations, which are not supported);
* modifiers: ``contains startswith endswith all re (i m s) cidr base64 base64offset windash cased
  lt lte gt gte exists``. Anything else is a validation error;
* condition: ``and or not ( )``, ``N of <pattern>``, ``all of <pattern>``, ``any of``, ``... of them``.
  Pipe aggregations (``| count() > 5``) are rejected.

All problems are collected (not just the first) so the UI / LLM advisor can show a useful error list.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import yaml

from tokiwa.detect.sigma.evaluator import (
    STAR,
    And,
    Condition,
    FieldCondition,
    KeywordCondition,
    Node,
    Not,
    Or,
    Quantifier,
    Ref,
    Selection,
    SigmaRule,
    StrPredicate,
    Token,
    ValuePredicate,
    apply_windash,
    cidr_predicate,
    compile_tokens,
    exists_predicate,
    has_wildcards,
    null_predicate,
    numeric_predicate,
    parse_wildcards,
    regex_predicate,
    string_predicate,
)
from tokiwa.detect.sigma.fieldmap import logsource_kinds, resolve_field, supported_categories

MAX_CONTENT_CHARS = 65_536
MAX_VALUES = 2_000  # total compiled values per rule (guards YAML alias bombs / runaway rules)
MAX_CONDITION_CHARS = 4_096
MAX_CONDITION_DEPTH = 64
MAX_TITLE_CHARS = 256

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")

MATCH_MODIFIERS = frozenset({"contains", "startswith", "endswith"})
TRANSFORM_MODIFIERS = frozenset({"base64", "base64offset", "windash"})
TYPE_MODIFIERS = frozenset({"re", "cidr", "lt", "lte", "gt", "gte", "exists"})
REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
SUPPORTED_MODIFIERS = (
    MATCH_MODIFIERS | TRANSFORM_MODIFIERS | TYPE_MODIFIERS | frozenset(REGEX_FLAGS) | {"all", "cased"}
)

_SAFE_LOADER: type[yaml.SafeLoader] = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_IDENT_RE = re.compile(r"^[A-Za-z0-9_.\-*?]+$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")


class SigmaError(ValueError):
    """Raised by :func:`parse_rule` with every validation problem found."""

    def __init__(self, errors: list[str], title: str | None = None) -> None:
        super().__init__("; ".join(errors) or "invalid Sigma rule")
        self.errors = errors
        self.title = title


@dataclass
class _Ctx:
    errors: list[str] = field(default_factory=list)
    values: int = 0

    def err(self, msg: str) -> None:
        if msg not in self.errors:
            self.errors.append(msg)

    def count(self, n: int = 1) -> bool:
        self.values += n
        if self.values > MAX_VALUES:
            self.err(f"rule too large: more than {MAX_VALUES} values")
            return False
        return True


# ---------------------------------------------------------------------------------------------------------
# YAML


def load_yaml(content: str) -> dict[str, Any]:
    """Parse a single Sigma YAML document. Raises SigmaError."""
    if not isinstance(content, str):
        raise SigmaError(["rule content must be a string"])
    if not content.strip():
        raise SigmaError(["rule content is empty"])
    if len(content) > MAX_CONTENT_CHARS:
        raise SigmaError([f"rule content too large (> {MAX_CONTENT_CHARS} characters)"])
    try:
        docs = [d for d in yaml.load_all(content, Loader=_SAFE_LOADER) if d is not None]
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else ""
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise SigmaError([f"invalid YAML{where}: {problem}"]) from exc
    if not docs:
        raise SigmaError(["rule content is empty"])
    if len(docs) > 1:
        raise SigmaError(["multiple YAML documents (rule collections) are not supported; submit one rule"])
    doc = docs[0]
    if not isinstance(doc, dict):
        raise SigmaError(["top-level YAML must be a mapping"])
    return doc


# ---------------------------------------------------------------------------------------------------------
# metadata


def _str_list(ctx: _Ctx, doc: dict[str, Any], key: str) -> tuple[str, ...]:
    value = doc.get(key)
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(v, str | int | float) for v in value):
        ctx.err(f"'{key}' must be a list of strings")
        return ()
    return tuple(str(v) for v in value)


def _scalar_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, date | datetime):
        return value.isoformat()
    return str(value)


# ---------------------------------------------------------------------------------------------------------
# values / modifiers


def _value_tokens(ctx: _Ctx, fld: str, value: Any) -> list[Token] | None:
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, int | float):
        return [str(value)]
    if isinstance(value, str):
        return parse_wildcards(value)
    ctx.err(f"field '{fld}': unsupported value type {type(value).__name__}")
    return None


def _b64_variants(ctx: _Ctx, fld: str, tokens: list[Token], offset: bool) -> list[list[Token]]:
    if has_wildcards(tokens):
        ctx.err(f"field '{fld}': wildcards are not allowed with base64 modifiers")
        return []
    raw = "".join(t for t in tokens if isinstance(t, str)).encode()
    if not offset:
        return [[base64.b64encode(raw).decode()]]
    # Same construction as pySigma's base64offset: the encoding of the value at the 3 possible byte offsets,
    # trimmed to the characters that do not depend on surrounding data.
    starts = (0, 2, 3)
    ends = (None, -3, -2)
    out: list[list[Token]] = []
    for i in range(3):
        enc = base64.b64encode(i * b" " + raw)[starts[i] : ends[(len(raw) + i) % 3]].decode()
        out.append([enc])
    return out


def _compile_field(ctx: _Ctx, key: str, value: Any) -> FieldCondition | None:
    name, *mods = key.split("|")
    name = name.strip()
    mods = [m.strip().lower() for m in mods]
    where = f"field '{key}'"
    if not name:
        ctx.err(f"{where}: empty field name (keyword selections must be a list of values)")
        return None
    unknown = [m for m in mods if m not in SUPPORTED_MODIFIERS]
    if unknown:
        ctx.err(f"{where}: unknown modifier(s) {', '.join(unknown)}")
        return None
    resolver = resolve_field(name)
    if resolver is None:
        ctx.err(
            f"{where}: unknown field '{name}' (not produced by TOKIWA events; see docs/detection/sigma.md)"
        )
        return None
    mset = set(mods)
    match_mods = mset & MATCH_MODIFIERS
    type_mods = mset & TYPE_MODIFIERS
    transforms = mset & TRANSFORM_MODIFIERS
    flags = mset & set(REGEX_FLAGS)
    if len(match_mods) > 1:
        ctx.err(f"{where}: only one of contains/startswith/endswith may be used")
        return None
    if len(type_mods) > 1:
        ctx.err(f"{where}: modifiers {', '.join(sorted(type_mods))} cannot be combined")
        return None
    if flags and "re" not in mset:
        ctx.err(f"{where}: modifiers i/m/s are only valid after 're'")
        return None
    conflicting = match_mods | transforms | ({"cased"} & mset)
    if type_mods and conflicting:
        other = ", ".join(sorted(conflicting))
        ctx.err(f"{where}: '{next(iter(type_mods))}' cannot be combined with {other}")
        return None
    if "windash" in transforms and transforms & {"base64", "base64offset"}:
        ctx.err(f"{where}: windash cannot be combined with base64 modifiers")
        return None
    if {"base64", "base64offset"} <= transforms:
        ctx.err(f"{where}: base64 and base64offset are mutually exclusive")
        return None
    require_all = "all" in mset
    if require_all and mset & {"exists", "base64offset"}:
        # exists takes one boolean; base64offset variants are alternatives of one value, never all at once.
        ctx.err(
            f"{where}: 'all' cannot be combined with {', '.join(sorted(mset & {'exists', 'base64offset'}))}"
        )
        return None

    values = value if isinstance(value, list) else [value]
    if not values:
        ctx.err(f"{where}: empty value list")
        return None
    if any(isinstance(v, list | dict) for v in values):
        ctx.err(f"{where}: values must be scalars (nested lists/maps are not allowed)")
        return None
    if not ctx.count(len(values)):
        return None

    preds: list[ValuePredicate] = []
    type_mod = next(iter(type_mods), None)
    for v in values:
        if v is None:
            if type_mod is not None or transforms or match_mods:
                ctx.err(f"{where}: null cannot be used with modifiers")
                return None
            preds.append(null_predicate())
            continue
        if type_mod == "exists":
            if not isinstance(v, bool):
                ctx.err(f"{where}: 'exists' expects true or false")
                return None
            preds.append(exists_predicate(v))
        elif type_mod in ("lt", "lte", "gt", "gte"):
            if isinstance(v, bool) or not isinstance(v, int | float):
                ctx.err(f"{where}: '{type_mod}' expects a number, got {v!r}")
                return None
            preds.append(numeric_predicate(type_mod, float(v)))
        elif type_mod == "cidr":
            try:
                net = ipaddress.ip_network(str(v).strip(), strict=False)
            except ValueError:
                ctx.err(f"{where}: invalid CIDR {v!r}")
                return None
            preds.append(cidr_predicate(net))
        elif type_mod == "re":
            if not isinstance(v, str):
                ctx.err(f"{where}: 're' expects a string pattern")
                return None
            fl = 0
            for f in flags:
                fl |= REGEX_FLAGS[f]
            try:
                rx = re.compile(v, fl)
            except re.error as exc:
                ctx.err(f"{where}: invalid regular expression {v!r}: {exc}")
                return None
            preds.append(regex_predicate(rx))
        else:
            tokens = _value_tokens(ctx, key, v)
            if tokens is None:
                return None
            variants: list[list[Token]] = [tokens]
            if "base64" in transforms or "base64offset" in transforms:
                variants = _b64_variants(ctx, key, tokens, offset="base64offset" in transforms)
                if not variants:
                    return None
                ctx.count(len(variants) - 1)
            if "windash" in transforms:
                variants = [apply_windash(t) for t in variants]
            # base64 text is case-significant: lower-casing it would match unrelated encodings.
            cased = "cased" in mset or bool(transforms & {"base64", "base64offset"})
            for toks in variants:
                if "contains" in match_mods:
                    toks = [STAR, *toks, STAR]
                elif "startswith" in match_mods:
                    toks = [*toks, STAR]
                elif "endswith" in match_mods:
                    toks = [STAR, *toks]
                preds.append(string_predicate(compile_tokens(toks, cased=cased)))
    return FieldCondition(field=name, resolver=resolver, predicates=tuple(preds), require_all=require_all)


def _compile_keywords(ctx: _Ctx, sel: str, values: list[Any]) -> KeywordCondition | None:
    if not ctx.count(len(values)):
        return None
    preds: list[StrPredicate] = []
    for v in values:
        if isinstance(v, bool | int | float | str):
            tokens = _value_tokens(ctx, sel, v)
            if tokens is None:
                return None
            preds.append(compile_tokens([STAR, *tokens, STAR]))
        else:
            ctx.err(f"selection '{sel}': keyword values must be strings")
            return None
    return KeywordCondition(predicates=tuple(preds))


def _compile_map(ctx: _Ctx, sel: str, mapping: dict[Any, Any]) -> tuple[Condition, ...] | None:
    if not mapping:
        ctx.err(f"selection '{sel}': empty map")
        return None
    conds: list[Condition] = []
    for k, v in mapping.items():
        if not isinstance(k, str):
            ctx.err(f"selection '{sel}': field names must be strings, got {k!r}")
            return None
        c = _compile_field(ctx, k, v)
        if c is None:
            return None
        conds.append(c)
    return tuple(conds)


def _compile_selection(ctx: _Ctx, name: str, node: Any) -> Selection | None:
    alternatives: list[tuple[Condition, ...]] = []
    if isinstance(node, dict):
        conds = _compile_map(ctx, name, node)
        if conds is None:
            return None
        alternatives.append(conds)
    elif isinstance(node, list):
        if not node:
            ctx.err(f"selection '{name}': empty list")
            return None
        keywords = [v for v in node if not isinstance(v, dict | list)]
        maps = [v for v in node if isinstance(v, dict)]
        if any(isinstance(v, list) for v in node):
            ctx.err(f"selection '{name}': nested lists are not allowed")
            return None
        if keywords:
            kw = _compile_keywords(ctx, name, keywords)
            if kw is None:
                return None
            alternatives.append((kw,))
        for m in maps:
            conds = _compile_map(ctx, name, m)
            if conds is None:
                return None
            alternatives.append(conds)
    elif isinstance(node, str | int | float) and not isinstance(node, bool):
        kw = _compile_keywords(ctx, name, [node])
        if kw is None:
            return None
        alternatives.append((kw,))
    else:
        ctx.err(f"selection '{name}': must be a map, a list of maps or a list of keywords")
        return None
    return Selection(name=name, alternatives=tuple(alternatives))


# ---------------------------------------------------------------------------------------------------------
# condition grammar

_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")
_KEYWORDS = frozenset({"and", "or", "not", "of", "them", "all", "any"})


class _CondParser:
    """Recursive descent: or_expr := and_expr ('or' and_expr)* ; and_expr := not_expr ('and' not_expr)* ;
    not_expr := 'not' not_expr | primary ; primary := '(' or_expr ')' | quantifier | identifier."""

    def __init__(self, text: str, identifiers: list[str]) -> None:
        self.text = text
        self.identifiers = identifiers
        self.tokens: list[str] = []
        pos = 0
        stripped = text.rstrip()
        while pos < len(stripped):
            m = _TOKEN_RE.match(stripped, pos)
            if m is None:  # pragma: no cover - the regex always matches non-empty remainder
                raise SigmaError([f"condition: cannot tokenize near {stripped[pos : pos + 20]!r}"])
            self.tokens.append(m.group(1))
            pos = m.end()
        self.i = 0
        self.depth = 0

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def peek_kw(self, offset: int = 0) -> str | None:
        j = self.i + offset
        return self.tokens[j].lower() if j < len(self.tokens) else None

    def take(self) -> str:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def fail(self, msg: str) -> SigmaError:
        return SigmaError([f"condition '{self.text}': {msg}"])

    def parse(self) -> Node:
        if not self.tokens:
            raise self.fail("empty condition")
        if any("|" in t for t in self.tokens):
            raise self.fail("aggregations ('| count() ...') are not supported")
        node = self.parse_or()
        if self.peek() is not None:
            raise self.fail(f"unexpected token {self.peek()!r}")
        return node

    def parse_or(self) -> Node:
        children = [self.parse_and()]
        while self.peek_kw() == "or":
            self.take()
            children.append(self.parse_and())
        return children[0] if len(children) == 1 else Or(tuple(children))

    def parse_and(self) -> Node:
        children = [self.parse_not()]
        while self.peek_kw() == "and":
            self.take()
            children.append(self.parse_not())
        return children[0] if len(children) == 1 else And(tuple(children))

    def parse_not(self) -> Node:
        if self.peek_kw() == "not":
            self.take()
            self.depth += 1
            if self.depth > MAX_CONDITION_DEPTH:
                raise self.fail("too deeply nested")
            node = Not(self.parse_not())
            self.depth -= 1
            return node
        return self.parse_primary()

    def parse_primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise self.fail("unexpected end of condition")
        if tok == "(":
            self.take()
            self.depth += 1
            if self.depth > MAX_CONDITION_DEPTH:
                raise self.fail("too deeply nested")
            node = self.parse_or()
            if self.peek() != ")":
                raise self.fail("missing ')'")
            self.take()
            self.depth -= 1
            return node
        if tok == ")":
            raise self.fail("unexpected ')'")
        low = tok.lower()
        if self.peek_kw(1) == "of" and (low in ("all", "any") or low.isdigit()):
            return self.parse_quantifier()
        if low in _KEYWORDS:
            raise self.fail(f"unexpected keyword {tok!r}")
        self.take()
        if not _IDENT_RE.match(tok):
            raise self.fail(f"invalid identifier {tok!r}")
        if "*" in tok or "?" in tok:
            raise self.fail(f"wildcard identifier {tok!r} must be used with '1 of' / 'all of'")
        if tok not in self.identifiers:
            raise self.fail(f"undefined search identifier {tok!r}")
        return Ref(tok)

    def parse_quantifier(self) -> Node:
        q = self.take().lower()
        self.take()  # 'of'
        target = self.peek()
        if target is None or target in ("(", ")"):
            raise self.fail(f"'{q} of' needs a search identifier pattern or 'them'")
        self.take()
        if target.lower() == "them":
            names = [n for n in self.identifiers if not n.startswith("_")]
        else:
            if not _IDENT_RE.match(target):
                raise self.fail(f"invalid identifier pattern {target!r}")
            names = [n for n in self.identifiers if fnmatch.fnmatchcase(n, target)]
        if not names:
            raise self.fail(f"pattern {target!r} matches no search identifier")
        if q == "all":
            minimum = len(names)
        elif q == "any":
            minimum = 1
        else:
            minimum = int(q)
            if minimum < 1:
                raise self.fail("'0 of' is not meaningful")
            if minimum > len(names):
                raise self.fail(f"'{q} of {target}' but only {len(names)} identifier(s) match")
        return Quantifier(minimum=minimum, names=tuple(sorted(names)))


def parse_condition(text: str, identifiers: list[str]) -> Node:
    if len(text) > MAX_CONDITION_CHARS:
        raise SigmaError([f"condition too long (> {MAX_CONDITION_CHARS} characters)"])
    return _CondParser(text, identifiers).parse()


# ---------------------------------------------------------------------------------------------------------
# rule


def _title_of(doc: dict[str, Any]) -> str | None:
    t = doc.get("title")
    return t.strip() if isinstance(t, str) and t.strip() else None


def compile_document(doc: dict[str, Any]) -> SigmaRule:
    """Validate a parsed YAML mapping and compile it. Raises SigmaError with all problems found."""
    ctx = _Ctx()
    title = _title_of(doc)
    if title is None:
        ctx.err("'title' is required (non-empty string)")
    elif len(title) > MAX_TITLE_CHARS:
        ctx.err(f"'title' too long (> {MAX_TITLE_CHARS} characters)")

    rule_id = doc.get("id")
    if rule_id is not None and (not isinstance(rule_id, str) or not _ID_RE.match(rule_id)):
        ctx.err("'id' must be a string of up to 64 characters [A-Za-z0-9._:-] (a UUID is recommended)")
        rule_id = None

    status = doc.get("status")
    if status is not None and (not isinstance(status, str) or status.lower() not in STATUSES):
        ctx.err(f"'status' must be one of {', '.join(STATUSES)}")
        status = None
    level = doc.get("level", "medium")
    if not isinstance(level, str) or level.lower() not in LEVELS:
        ctx.err(f"'level' must be one of {', '.join(LEVELS)}")
        level = "medium"
    description = doc.get("description") or ""
    if not isinstance(description, str):
        ctx.err("'description' must be a string")
        description = ""
    tags = _str_list(ctx, doc, "tags")
    references = _str_list(ctx, doc, "references")
    falsepositives = _str_list(ctx, doc, "falsepositives")

    logsource_raw = doc.get("logsource")
    logsource: dict[str, str] = {}
    kinds = None
    if not isinstance(logsource_raw, dict) or not logsource_raw:
        ctx.err("'logsource' is required (mapping with category / product / service)")
    else:
        logsource = {str(k): str(v) for k, v in logsource_raw.items() if v is not None}
        if not any(logsource.get(k) for k in ("category", "product", "service")):
            ctx.err("'logsource' needs at least one of category / product / service")
        else:
            kinds = logsource_kinds(logsource)
            if not kinds:
                ctx.err(
                    f"unsupported logsource {logsource!r}: TOKIWA ingests categories "
                    f"{', '.join(supported_categories())} (or product: tokiwa + service: <event kind>)"
                )

    selections: dict[str, Selection] = {}
    condition: Node | None = None
    detection = doc.get("detection")
    if not isinstance(detection, dict) or not detection:
        ctx.err("'detection' is required (mapping with search identifiers and 'condition')")
    else:
        cond_raw = detection.get("condition")
        names: list[str] = []
        for name, node in detection.items():
            if name in ("condition", "timeframe"):
                continue
            if not isinstance(name, str) or not _IDENT_RE.match(name) or "*" in name or "?" in name:
                ctx.err(f"invalid search identifier {name!r}")
                continue
            if name.lower() in _KEYWORDS:
                ctx.err(f"search identifier {name!r} is a reserved word")
                continue
            names.append(name)
            sel = _compile_selection(ctx, name, node)
            if sel is not None:
                selections[name] = sel
        if not names:
            ctx.err("'detection' has no search identifiers")
        if cond_raw is None:
            ctx.err("'detection.condition' is required")
        else:
            conds = cond_raw if isinstance(cond_raw, list) else [cond_raw]
            nodes: list[Node] = []
            for c in conds:
                if not isinstance(c, str):
                    ctx.err("'detection.condition' must be a string or a list of strings")
                    continue
                try:
                    nodes.append(parse_condition(c, names))
                except SigmaError as exc:
                    for e in exc.errors:
                        ctx.err(e)
            if nodes and len(nodes) == len(conds):
                condition = nodes[0] if len(nodes) == 1 else Or(tuple(nodes))

    if ctx.errors or title is None or condition is None or kinds is None:
        raise SigmaError(ctx.errors or ["invalid Sigma rule"], title=title)
    return SigmaRule(
        title=title,
        id=rule_id,
        status=status.lower() if isinstance(status, str) else None,
        level=level.lower(),
        description=description.strip(),
        author=_scalar_str(doc.get("author")),
        tags=tuple(t.strip() for t in tags),
        references=references,
        falsepositives=falsepositives,
        logsource=logsource,
        kinds=kinds,
        selections=selections,
        condition=condition,
        raw=doc,
    )


def parse_rule(content: str) -> SigmaRule:
    """YAML text -> compiled rule. Raises :class:`SigmaError` (``.errors`` lists every problem)."""
    doc = load_yaml(content)
    return compile_document(doc)


def validate_rule(content: str) -> tuple[bool, list[str], str | None]:
    """Public validator used by the rules API and the intel advisor (LLM-proposed rules).

    Returns ``(valid, errors, title)``; ``title`` is filled whenever the YAML has one, even if invalid.
    Never raises.
    """
    try:
        rule = parse_rule(content)
    except SigmaError as exc:
        title = exc.title
        if title is None:
            try:
                title = _title_of(load_yaml(content))
            except SigmaError:
                title = None
        return False, list(exc.errors), title
    except Exception as exc:  # defensive: the validator must never crash its caller
        return False, [f"internal error while validating rule: {type(exc).__name__}"], None
    return True, [], rule.title
