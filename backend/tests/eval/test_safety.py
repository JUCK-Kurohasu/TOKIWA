"""Simulator target restriction (AGENTS.md §2.7)."""

from __future__ import annotations

import pytest

from tokiwa.eval.safety import TargetNotAllowedError, check_target, ip_is_lab, same_origin_path


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080",
        "http://api.localhost/",
        "http://127.0.0.1:8080",
        "http://10.1.2.3",
        "http://172.28.0.10:8080",
        "https://192.168.1.20",
        "http://[::1]:8080",
        "http://[fd00::5]/",
    ],
)
def test_lab_targets_allowed(url: str) -> None:
    assert check_target(url) == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8",
        "http://169.254.169.254/latest/meta-data/",  # link-local cloud metadata
        "http://[fe80::1]/",
        "http://0.0.0.0/",
        "ftp://127.0.0.1/",
        "http://user:pw@127.0.0.1/",
        "http:///nohost",
    ],
)
def test_non_lab_targets_refused(url: str) -> None:
    with pytest.raises(TargetNotAllowedError):
        check_target(url)


def test_hostnames_must_resolve_to_lab_addresses() -> None:
    assert check_target("http://gate:8080", resolver=lambda h: ["172.28.0.10"]) == "http://gate:8080"
    with pytest.raises(TargetNotAllowedError):
        check_target("http://example.com", resolver=lambda h: ["93.184.216.34"])
    with pytest.raises(TargetNotAllowedError):  # mixed answers are refused too
        check_target("http://gate", resolver=lambda h: ["10.0.0.1", "93.184.216.34"])

    def fail(host: str) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(TargetNotAllowedError):
        check_target("http://nope.invalid", resolver=fail)


def test_override_flag_allows_owned_targets_but_not_other_schemes() -> None:
    assert check_target("https://shop.example.com/", allow_any=True) == "https://shop.example.com"
    with pytest.raises(TargetNotAllowedError):
        check_target("file:///etc/passwd", allow_any=True)


def test_ip_is_lab_and_same_origin() -> None:
    assert ip_is_lab("::ffff:10.0.0.1")
    assert not ip_is_lab("not-an-ip")
    base = "http://gate:8080"
    assert same_origin_path(base, "/api/internal/debug") == "/api/internal/debug"
    assert same_origin_path(base, "http://gate:8080/x?y=1") == "/x?y=1"
    assert same_origin_path(base, "https://evil.invalid/steal") is None
    assert same_origin_path(base, "//evil.invalid/x") is None
    assert same_origin_path(base, "relative/path") is None
