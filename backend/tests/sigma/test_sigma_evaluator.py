"""Evaluator semantics: modifiers, wildcards, case handling, conditions, keywords, field mapping."""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any

import pytest

from tokiwa.detect.sigma import SigmaRule, parse_rule
from tokiwa.schemas.events import (
    Endpoint,
    Event,
    EventKind,
    HostInfo,
    HttpInfo,
    LLMAppInfo,
    ProcessInfo,
)

MakeEvent = Callable[..., Event]


def rule(detection: str, *, logsource: str = "category: webserver", extra: str = "") -> SigmaRule:
    body = "\n".join("  " + line for line in detection.strip("\n").splitlines())
    return parse_rule(f"title: t\nlogsource:\n  {logsource}\n{extra}detection:\n{body}\n")


def http(**kw: Any) -> Event:
    ip = kw.pop("ip", "203.0.113.10")
    return Event(kind=EventKind.HTTP, dataset="gate.http", source=Endpoint(ip=ip), http=HttpInfo(**kw))


# ---------------------------------------------------------------------------------------------------------
# plain values / wildcards / case


def test_plain_value_is_full_match_and_case_insensitive() -> None:
    r = rule("sel:\n  cs-method: post\ncondition: sel")
    assert r.matches(http(method="POST"))
    assert not r.matches(http(method="POSTX"))


def test_wildcards_star_and_question_mark() -> None:
    r = rule("sel:\n  cs-uri-stem: '/admin/*/edit?'\ncondition: sel")
    assert r.matches(http(path="/admin/users/42/edit1"))
    assert r.matches(http(path="/ADMIN/x/EDITs"))
    assert not r.matches(http(path="/admin/x/edit"))  # ? needs exactly one char


def test_escaped_wildcards_are_literal() -> None:
    r = rule("sel:\n  cs-uri-query|contains: '7\\*7'\ncondition: sel")
    assert r.matches(http(path="/", query="x={{7*7}}"))
    assert not r.matches(http(path="/", query="x=7777"))
    r2 = rule("sel:\n  cs-uri-query: 'a\\?'\ncondition: sel")
    assert r2.matches(http(path="/", query="a?"))
    assert not r2.matches(http(path="/", query="ab"))


def test_backslash_not_before_wildcard_is_literal() -> None:
    r = rule("sel:\n  cs-uri-query|contains: '..\\'\ncondition: sel")
    assert r.matches(http(path="/", query="f=..\\..\\win.ini"))


def test_cased_modifier() -> None:
    r = rule("sel:\n  request_body|cased|contains: 'rO0AB'\ncondition: sel")
    assert r.matches(http(path="/", request_body="x=rO0ABXNy"))
    assert not r.matches(http(path="/", request_body="x=ro0abxny"))


def test_value_list_is_or_and_all_is_and() -> None:
    r_or = rule("sel:\n  cs-uri-query|contains: [aaa, bbb]\ncondition: sel")
    r_all = rule("sel:\n  cs-uri-query|contains|all: [aaa, bbb]\ncondition: sel")
    e1 = http(path="/", query="aaa")
    e2 = http(path="/", query="aaa&bbb")
    assert r_or.matches(e1) and r_or.matches(e2)
    assert not r_all.matches(e1) and r_all.matches(e2)


def test_startswith_endswith() -> None:
    r = rule("a:\n  cs-uri-stem|startswith: /api/\nb:\n  cs-uri-stem|endswith: .php\ncondition: a and b")
    assert r.matches(http(path="/api/v1/index.PHP"))
    assert not r.matches(http(path="/x/api/index.php"))


def test_numbers_and_numeric_comparisons() -> None:
    assert rule("sel:\n  sc-status: 404\ncondition: sel").matches(http(path="/", status=404))
    assert rule("sel:\n  sc-status: '40*'\ncondition: sel").matches(http(path="/", status=403))
    gte = rule("sel:\n  sc-status|gte: 500\ncondition: sel")
    assert gte.matches(http(path="/", status=503)) and not gte.matches(http(path="/", status=499))
    lt = rule("sel:\n  cs-bytes|lt: 10\ncondition: sel")
    assert lt.matches(http(path="/", request_body_size=3)) and not lt.matches(
        http(path="/", request_body_size=10)
    )
    assert rule("sel:\n  cs-bytes|lte: 10\ncondition: sel").matches(http(path="/", request_body_size=10))
    assert rule("sel:\n  cs-bytes|gt: 10\ncondition: sel").matches(http(path="/", request_body_size=11))
    assert not lt.matches(http(path="/"))  # missing field never compares


def test_regex_modifier_and_flags() -> None:
    r = rule("sel:\n  c-useragent|re: '^curl/[0-9.]+$'\ncondition: sel")
    assert r.matches(http(path="/", user_agent="curl/8.5.0"))
    assert not r.matches(http(path="/", user_agent="CURL/8.5.0"))  # re is case-sensitive by default
    ri = rule("sel:\n  c-useragent|re|i: '^curl/'\ncondition: sel")
    assert ri.matches(http(path="/", user_agent="CURL/8.5.0"))
    rs = rule("sel:\n  request_body|re|s: 'a.b'\ncondition: sel")
    assert rs.matches(http(path="/", request_body="a\nb"))
    rm = rule("sel:\n  request_body|re|m: '^second$'\ncondition: sel")
    assert rm.matches(http(path="/", request_body="first\nsecond\nthird"))


def test_cidr_modifier() -> None:
    r = rule("sel:\n  c-ip|cidr: [10.0.0.0/8, '2001:db8::/32']\ncondition: sel")
    assert r.matches(http(path="/", ip="10.20.30.40"))
    assert r.matches(http(path="/", ip="2001:db8::1"))
    assert not r.matches(http(path="/", ip="192.0.2.1"))
    assert not r.matches(http(path="/", ip="not-an-ip"))


def test_exists_and_null() -> None:
    ex = rule("sel:\n  cs-referer|exists: true\ncondition: sel")
    nex = rule("sel:\n  cs-referer|exists: false\ncondition: sel")
    null = rule("sel:\n  cs-referer: null\ncondition: sel")
    with_ref = http(path="/", referrer="https://example.com/")
    without = http(path="/")
    assert ex.matches(with_ref) and not ex.matches(without)
    assert nex.matches(without) and not nex.matches(with_ref)
    assert null.matches(without) and not null.matches(with_ref)


def test_empty_string_value() -> None:
    r = rule("sel:\n  cs-uri-query: ''\ncondition: sel")
    assert r.matches(http(path="/", query=""))
    assert not r.matches(http(path="/", query="a=1"))


def test_base64_modifier() -> None:
    enc = base64.b64encode(b"/bin/sh").decode()
    r = rule("sel:\n  request_body|base64|contains: /bin/sh\ncondition: sel")
    assert r.matches(http(path="/", request_body=f"cmd={enc}"))
    assert not r.matches(http(path="/", request_body="cmd=/bin/sh"))


@pytest.mark.parametrize("prefix", [b"", b"x", b"xy", b"hello world: "])
def test_base64offset_finds_value_at_any_alignment(prefix: bytes) -> None:
    r = rule(
        "sel:\n  prompt|base64offset|contains: ignore previous instructions\ncondition: sel",
        logsource="category: llm_app",
    )
    blob = base64.b64encode(prefix + b"ignore previous instructions" + b" now").decode()
    ev = Event(kind=EventKind.LLM_APP, dataset="app.llm", llm_app=LLMAppInfo(prompt=f"decode: {blob}"))
    assert r.matches(ev)


def test_base64offset_is_case_sensitive() -> None:
    r = rule(
        "sel:\n  prompt|base64offset|contains: ignore previous instructions\ncondition: sel",
        logsource="category: llm_app",
    )
    blob = base64.b64encode(b"ignore previous instructions").decode().swapcase()
    ev = Event(kind=EventKind.LLM_APP, dataset="app.llm", llm_app=LLMAppInfo(prompt=blob))
    assert not r.matches(ev)
    original = base64.b64encode(b"ignore previous instructions").decode()
    assert r.matches(Event(kind=EventKind.LLM_APP, dataset="app.llm", llm_app=LLMAppInfo(prompt=original)))


def test_windash_modifier() -> None:
    r = rule(
        "sel:\n  CommandLine|windash|contains: ' -enc '\ncondition: sel",
        logsource="category: process_creation",
    )

    def proc(cmd: str) -> Event:
        return Event(kind=EventKind.PROCESS, dataset="host.proc", process=ProcessInfo(cmdline=cmd))

    assert r.matches(proc("powershell.exe -enc AAAA"))
    assert r.matches(proc("powershell.exe /enc AAAA"))
    assert r.matches(proc("powershell.exe \u2013enc AAAA"))
    assert not r.matches(proc("powershell.exe enc AAAA"))


# ---------------------------------------------------------------------------------------------------------
# selections / conditions


def test_selection_map_is_and_list_of_maps_is_or() -> None:
    r_and = rule("sel:\n  cs-method: POST\n  cs-uri-stem: /login\ncondition: sel")
    r_or = rule("sel:\n  - cs-method: POST\n  - cs-uri-stem: /login\ncondition: sel")
    post_other = http(method="POST", path="/other")
    post_login = http(method="POST", path="/login")
    assert not r_and.matches(post_other) and r_and.matches(post_login)
    assert r_or.matches(post_other) and r_or.matches(http(method="GET", path="/login"))


CONDITIONS = """
a:
  cs-uri-query|contains: aaa
b:
  cs-uri-query|contains: bbb
c:
  cs-uri-query|contains: ccc
_helper:
  cs-uri-query|contains: zzz
"""


@pytest.mark.parametrize(
    ("condition", "query", "expected"),
    [
        ("a and b", "aaa bbb", True),
        ("a and b", "aaa", False),
        ("a or b", "bbb", True),
        ("not a", "bbb", True),
        ("not a", "aaa", False),
        ("a and not (b or c)", "aaa", True),
        ("a and not (b or c)", "aaa ccc", False),
        ("(a or b) and c", "bbb ccc", True),
        ("a or b and c", "aaa", True),  # and binds tighter than or
        ("not a and b", "bbb", True),  # not binds tighter than and
        ("1 of a*", "aaa", True),
        ("1 of them", "ccc", True),
        ("all of them", "aaa bbb ccc", True),  # 'them' excludes _helper
        ("all of them", "aaa bbb", False),
        ("2 of them", "aaa ccc", True),
        ("2 of them", "aaa", False),
        ("any of them", "bbb", True),
        ("1 of _*", "zzz", True),
        ("all of _*", "zzz", True),
    ],
)
def test_condition_expressions(condition: str, query: str, expected: bool) -> None:
    r = rule(CONDITIONS + f"condition: {condition}")
    assert r.matches(http(path="/", query=query)) is expected


def test_operator_keywords_are_case_insensitive() -> None:
    r = rule(CONDITIONS + "condition: a AND NOT b")
    assert r.matches(http(path="/", query="aaa"))


def test_condition_list_is_or() -> None:
    r = rule(CONDITIONS + "condition:\n  - a and b\n  - c")
    assert r.matches(http(path="/", query="ccc"))
    assert r.matches(http(path="/", query="aaa bbb"))
    assert not r.matches(http(path="/", query="aaa"))


def test_match_reports_true_selections() -> None:
    r = rule(CONDITIONS + "condition: 1 of them")
    res = r.match(http(path="/", query="bbb"))
    assert res is not None and "b" in res.matched and "a" not in res.matched


def test_keywords_search_common_text_fields() -> None:
    r = rule("keywords:\n  - 'evil-marker'\n  - 'other-marker'\ncondition: keywords")
    assert r.matches(http(path="/x", user_agent="Mozilla evil-marker"))
    assert r.matches(http(path="/x", request_body="... OTHER-MARKER ..."))
    assert not r.matches(http(path="/x", user_agent="Mozilla"))
    msg = Event(kind=EventKind.HTTP, dataset="nginx.access", message="GET /evil-marker HTTP/1.1")
    assert r.matches(msg)


# ---------------------------------------------------------------------------------------------------------
# field mapping


def test_url_decoded_variants_are_matched() -> None:
    r = rule("sel:\n  cs-uri-query|contains: '../'\ncondition: sel")
    assert r.matches(http(path="/", query="f=%2e%2e%2fetc%2fpasswd"))
    assert r.matches(http(path="/", query="f=%252e%252e%252f"))  # double encoded
    r2 = rule("sel:\n  cs-uri-query|contains: 'union select'\ncondition: sel")
    assert r2.matches(http(path="/", query="id=1+union+select+1"))


def test_c_uri_combines_path_and_query() -> None:
    r = rule("sel:\n  c-uri: '/a/b?x=1'\ncondition: sel")
    assert r.matches(http(path="/a/b", query="x=1"))
    assert rule("sel:\n  c-uri: '/a/b'\ncondition: sel").matches(http(path="/a/b"))


def test_ecs_and_sigma_aliases_resolve_to_same_attribute() -> None:
    ev = http(
        path="/p", method="PUT", user_agent="UA-1", host="app.lab", status=201, ip="198.51.100.7", query="q=1"
    )
    for fld, val in [
        ("url.path", "/p"),
        ("cs-uri-stem", "/p"),
        ("http.request.method", "PUT"),
        ("user_agent.original", "UA-1"),
        ("c-useragent", "UA-1"),
        ("cs-host", "app.lab"),
        ("http.response.status_code", 201),
        ("source.ip", "198.51.100.7"),
        ("c-ip", "198.51.100.7"),
        ("url.query", "q=1"),
    ]:
        assert rule(f"sel:\n  {fld}: '{val}'\ncondition: sel").matches(ev), fld


def test_user_agent_falls_back_to_header() -> None:
    ev = http(path="/", headers={"user-agent": "sqlmap/1.8"})
    assert rule("sel:\n  c-useragent|contains: sqlmap\ncondition: sel").matches(ev)


def test_dotted_path_fallback_headers_labels_and_lists() -> None:
    ev = http(path="/", headers={"x-forwarded-for": "10.9.9.9"})
    ev.labels["env"] = "prod"
    ev.tags.append("from-gate")
    assert rule("sel:\n  http.headers.x-forwarded-for|cidr: 10.0.0.0/8\ncondition: sel").matches(ev)
    assert rule("sel:\n  labels.env: prod\ncondition: sel").matches(ev)
    assert rule("sel:\n  tags: from-gate\ncondition: sel").matches(ev)


def test_host_name_alias() -> None:
    ev = Event(
        kind=EventKind.HTTP, dataset="nginx.access", host=HostInfo(name="web-1"), http=HttpInfo(path="/")
    )
    assert rule("sel:\n  host.name: web-1\ncondition: sel").matches(ev)


def test_logsource_limits_event_kinds() -> None:
    web = rule("keywords:\n  - marker\ncondition: keywords")
    llm = Event(kind=EventKind.LLM_APP, dataset="app.llm", llm_app=LLMAppInfo(prompt="marker"))
    assert not web.matches(llm)
    assert web.kinds == frozenset({EventKind.HTTP})
    any_kind = rule("keywords:\n  - marker\ncondition: keywords", logsource="product: tokiwa")
    assert any_kind.matches(llm)
    only_llm = rule(
        "keywords:\n  - marker\ncondition: keywords", logsource="product: tokiwa\n  service: llm_app"
    )
    assert only_llm.matches(llm) and not only_llm.matches(http(path="/marker"))


def test_prompt_field_on_llm_app_events_and_llm_app_http_paths(settings: Any) -> None:
    r = rule("sel:\n  prompt|contains: ignore previous\ncondition: sel", logsource="category: llm_app")
    hook = Event(
        kind=EventKind.LLM_APP, dataset="app.llm", llm_app=LLMAppInfo(prompt="Please IGNORE previous")
    )
    to_chat = http(path="/api/chat", method="POST", request_body='{"q": "ignore previous rules"}')
    elsewhere = http(path="/upload", method="POST", request_body='{"q": "ignore previous rules"}')
    assert r.matches(hook)
    assert r.matches(to_chat)
    assert not r.matches(elsewhere)  # body is only a "prompt" on protected LLM app paths


def test_long_values_are_truncated_not_crashing() -> None:
    r = rule("sel:\n  request_body|re: 'needle$'\ncondition: sel")
    assert not r.matches(http(path="/", request_body="a" * 200_000 + "needle"))
