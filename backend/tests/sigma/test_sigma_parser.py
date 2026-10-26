"""Parser / validator: required structure, modifier validation, condition errors, limits."""

from __future__ import annotations

import pytest

from tokiwa.detect.sigma import SigmaError, parse_rule, validate_rule
from tokiwa.schemas.events import EventKind

VALID = """
title: Valid rule
id: 0b1c2d3e-0000-4000-8000-000000000001
status: experimental
level: high
description: d
tags: [attack.initial_access, attack.t1190]
falsepositives: [none]
logsource:
  category: webserver
detection:
  sel:
    cs-uri-query|contains: evil
  condition: sel
"""


def errors_of(content: str) -> list[str]:
    valid, errors, _ = validate_rule(content)
    assert not valid
    assert errors
    return errors


def test_valid_rule_metadata() -> None:
    valid, errors, title = validate_rule(VALID)
    assert (valid, errors, title) == (True, [], "Valid rule")
    r = parse_rule(VALID)
    assert r.id == "0b1c2d3e-0000-4000-8000-000000000001"
    assert r.level == "high" and r.status == "experimental"
    assert r.tags == ("attack.initial_access", "attack.t1190")
    assert r.kinds == frozenset({EventKind.HTTP})


def test_level_defaults_to_medium_and_id_is_optional() -> None:
    r = parse_rule("title: x\nlogsource: {category: proxy}\ndetection: {s: {c-uri: /}, condition: s}")
    assert r.level == "medium" and r.id is None


@pytest.mark.parametrize(
    ("content", "needle"),
    [
        ("", "empty"),
        ("title: [unclosed", "invalid YAML"),
        ("- a\n- b", "mapping"),
        (VALID + "---\n" + VALID, "multiple YAML documents"),
        (VALID.replace("title: Valid rule", "title: ''"), "'title' is required"),
        (VALID.replace("level: high", "level: severe"), "'level' must be one of"),
        (VALID.replace("status: experimental", "status: beta"), "'status' must be one of"),
        (VALID.replace("id: 0b1c2d3e-0000-4000-8000-000000000001", "id: 'has spaces in id'"), "'id' must be"),
        (VALID.replace("category: webserver", "product: windows"), "unsupported logsource"),
        (VALID.replace("category: webserver", "category: registry_event"), "unsupported logsource"),
        ("title: x\ndetection: {s: {c-uri: /}, condition: s}", "'logsource' is required"),
        ("title: x\nlogsource: {category: webserver}", "'detection' is required"),
        ("title: x\nlogsource: {category: webserver}\ndetection: {s: {c-uri: /}}", "condition' is required"),
        ("title: x\nlogsource: {category: webserver}\ndetection: {condition: s}", "no search identifiers"),
        (VALID.replace("cs-uri-query|contains", "cs-uri-query|contians"), "unknown modifier(s) contians"),
        (VALID.replace("cs-uri-query|contains", "cs-uri-query|expand"), "unknown modifier(s) expand"),
        (VALID.replace("cs-uri-query|contains", "TargetFilename|contains"), "unknown field 'TargetFilename'"),
        (VALID.replace("cs-uri-query|contains", "http.nonexistent"), "unknown field"),
        (VALID.replace("cs-uri-query|contains", "cs-uri-query|contains|startswith"), "only one of"),
        (VALID.replace("cs-uri-query|contains: evil", "c-ip|cidr: 999.1.1.1/8"), "invalid CIDR"),
        (
            VALID.replace("cs-uri-query|contains: evil", "c-ip|cidr|contains: 10.0.0.0/8"),
            "cannot be combined",
        ),
        (VALID.replace("cs-uri-query|contains: evil", "sc-status|gt: abc"), "expects a number"),
        (VALID.replace("cs-uri-query|contains: evil", "cs-referer|exists: maybe"), "expects true or false"),
        (
            VALID.replace("cs-uri-query|contains: evil", "c-useragent|re: '(unclosed'"),
            "invalid regular expression",
        ),
        (VALID.replace("cs-uri-query|contains: evil", "c-useragent|i: x"), "only valid after 're'"),
        (
            VALID.replace("cs-uri-query|contains: evil", "request_body|base64: 'a*b'"),
            "wildcards are not allowed",
        ),
        (
            VALID.replace("cs-uri-query|contains: evil", "request_body|base64offset|all: [a, b]"),
            "'all' cannot",
        ),
        (VALID.replace("cs-uri-query|contains: evil", "cs-uri-query: []"), "empty value list"),
        (VALID.replace("cs-uri-query|contains: evil", "cs-uri-query: [[a]]"), "scalars"),
        (VALID.replace("cs-uri-query|contains: evil", "cs-uri-query: {a: b}"), "scalars"),
        (
            VALID.replace("condition: sel", "condition: sel and missing"),
            "undefined search identifier 'missing'",
        ),
        (VALID.replace("condition: sel", "condition: sel and"), "unexpected end"),
        (VALID.replace("condition: sel", "condition: (sel"), "missing ')'"),
        (VALID.replace("condition: sel", "condition: sel)"), "unexpected token"),
        (VALID.replace("condition: sel", "condition: sel | count() > 5"), "aggregations"),
        (VALID.replace("condition: sel", "condition: 1 of nothing*"), "matches no search identifier"),
        (VALID.replace("condition: sel", "condition: 3 of sel*"), "only 1 identifier"),
        (VALID.replace("condition: sel", "condition: sel*"), "must be used with"),
        (VALID.replace("condition: sel", "condition: sel or or sel"), "unexpected keyword"),
        (VALID.replace("condition: sel", "condition: '(((((((('"), "unexpected end"),
        (VALID.replace("condition: sel", "condition: " + "(" * 70 + "sel" + ")" * 70), "too deeply nested"),
        (VALID.replace("condition: sel", "condition: " + "not " * 70 + "sel"), "too deeply nested"),
    ],
)
def test_invalid_rules_are_rejected_with_reason(content: str, needle: str) -> None:
    errors = errors_of(content)
    assert any(needle in e for e in errors), errors


def test_all_errors_are_collected() -> None:
    content = """
title: multi
level: nope
logsource: {category: webserver}
detection:
  a:
    cs-uri-query|wat: x
  b:
    unknownfield: y
  condition: a and b and c
"""
    errors = errors_of(content)
    assert len(errors) >= 4
    assert any("level" in e for e in errors)
    assert any("wat" in e for e in errors)
    assert any("unknownfield" in e for e in errors)
    assert any("'c'" in e for e in errors)


def test_validate_returns_title_even_when_invalid() -> None:
    valid, errors, title = validate_rule("title: Broken one\nlogsource: {category: webserver}\ndetection: {}")
    assert not valid and errors and title == "Broken one"


def test_validate_never_raises_on_garbage() -> None:
    for junk in ["\x00\x01", "{{{{", "!!python/object:os.system 'id'", "title: !!binary aGVsbG8="]:
        valid, errors, _ = validate_rule(junk)
        assert valid is False and errors


def test_unsafe_yaml_tags_are_not_constructed() -> None:
    content = VALID.replace("description: d", "description: !!python/object/apply:os.system ['true']")
    errors = errors_of(content)
    assert any("invalid YAML" in e for e in errors)


def test_parse_rule_raises_sigma_error_with_all_errors() -> None:
    with pytest.raises(SigmaError) as exc:
        parse_rule(VALID.replace("level: high", "level: x").replace("condition: sel", "condition: zz"))
    assert len(exc.value.errors) == 2


def test_size_limits() -> None:
    huge = VALID + "\n# " + "x" * 70_000
    assert any("too large" in e for e in errors_of(huge))
    many = "\n".join(f"      - v{i}" for i in range(2_100))
    content = f"title: big\nlogsource: {{category: webserver}}\ndetection:\n  s:\n    c-uri|contains:\n{many}\n  condition: s\n"
    assert any("too large" in e for e in errors_of(content))


def test_yaml_alias_expansion_is_bounded() -> None:
    # Each map aliases the same big list; the value counter stops runaway expansion.
    values = "\n".join(f"    - v{i}" for i in range(400))
    content = (
        "title: bomb\nlogsource: {category: webserver}\n"
        f"x: &big\n{values}\n"
        "detection:\n  s:\n" + "".join("    - c-uri|contains: *big\n" for _ in range(10)) + "  condition: s\n"
    )
    assert any("too large" in e for e in errors_of(content))


def test_reserved_and_invalid_identifiers() -> None:
    content = VALID.replace("  sel:\n", "  and:\n").replace("condition: sel", "condition: and")
    assert errors_of(content)
    content = VALID.replace("  sel:\n", "  'bad name':\n").replace("condition: sel", "condition: sel")
    assert any("invalid search identifier" in e for e in errors_of(content))


def test_keyword_selection_forms() -> None:
    r = parse_rule("title: k\nlogsource: {category: webserver}\ndetection:\n  kw: just-one\n  condition: kw")
    assert r.selections["kw"].alternatives
    r2 = parse_rule(
        "title: k\nlogsource: {category: webserver}\ndetection:\n"
        "  mixed:\n    - kw-one\n    - cs-method: POST\n  condition: mixed"
    )
    assert len(r2.selections["mixed"].alternatives) == 2
