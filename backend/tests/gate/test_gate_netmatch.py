from __future__ import annotations

import ipaddress
import random
import time

import pytest

from tokiwa.gate.netmatch import IpTable, parse_ip, parse_network


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.7", "203.0.113.7"),
        (" 203.0.113.7 ", "203.0.113.7"),
        ("203.0.113.7:51234", "203.0.113.7"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("::ffff:198.51.100.4", "198.51.100.4"),  # dual-stack listener folds to IPv4
        ("unknown", None),
        ("", None),
        (None, None),
        ("[broken", None),
        ("example.com", None),
    ],
)
def test_parse_ip(raw: str | None, expected: str | None) -> None:
    ip = parse_ip(raw)
    assert (str(ip) if ip else None) == expected


def test_parse_network_tolerates_host_bits_and_maps_v4() -> None:
    assert str(parse_network("10.1.2.3/8")) == "10.0.0.0/8"
    assert str(parse_network("::ffff:192.0.2.0/120")) == "192.0.2.0/24"
    assert parse_network("10.0.0.0/33") is None
    assert parse_network("nope") is None


def test_longest_prefix_match() -> None:
    table, invalid = IpTable[int].build(
        [("10.0.0.0/8", 100), ("10.1.0.0/16", 10), ("10.1.2.3", 1), ("2001:db8::/32", 7)]
    )
    assert invalid == []
    assert table.lookup(parse_ip("10.1.2.3")) == ("10.1.2.3/32", 1)
    assert table.lookup(parse_ip("10.1.9.9")) == ("10.1.0.0/16", 10)
    assert table.lookup(parse_ip("10.200.0.1")) == ("10.0.0.0/8", 100)
    assert table.lookup(parse_ip("11.0.0.1")) is None
    assert table.lookup(parse_ip("2001:db8:ffff::1")) == ("2001:db8::/32", 7)
    assert table.lookup(parse_ip("2001:db9::1")) is None
    assert table.lookup(None) is None
    assert len(table) == 4


def test_v4_mapped_policy_entry_matches_ipv4_client() -> None:
    table, _ = IpTable[bool].build([("::ffff:192.0.2.0/120", True)])
    assert "192.0.2.77" in table
    assert "::ffff:192.0.2.77" in table
    assert "192.0.3.1" not in table


def test_catch_all_and_invalid_entries() -> None:
    table, invalid = IpTable[bool].build([("0.0.0.0/0", True), ("not-an-ip", True), ("1.2.3.4/40", True)])
    assert invalid == ["not-an-ip", "1.2.3.4/40"]
    assert "8.8.8.8" in table
    assert "2001:db8::1" not in table  # IPv4 catch-all does not cover IPv6
    assert "garbage" not in table
    assert 42 not in table


def test_duplicate_networks_use_merge() -> None:
    stricter, _ = IpTable[int].build([("10.0.0.0/8", 100), ("10.0.0.0/8", 5)], merge=min)
    assert stricter.lookup(parse_ip("10.0.0.1")) == ("10.0.0.0/8", 5)
    first, _ = IpTable[int].build([("10.0.0.0/8", 100), ("10.0.0.0/8", 5)])
    assert first.lookup(parse_ip("10.0.0.1")) == ("10.0.0.0/8", 100)


def test_add_after_build_is_visible() -> None:
    table: IpTable[bool] = IpTable()
    table.add("192.0.2.0/24", True)  # no explicit freeze(): lookup refreshes the order lazily
    assert "192.0.2.1" in table
    table.add("198.51.100.1", True)
    assert "198.51.100.1" in table


def test_large_tables_stay_fast_and_correct() -> None:
    """20k host entries + 2k /24s: lookups cost one dict probe per distinct prefix length, not per entry."""
    rng = random.Random(7)
    hosts = {str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(20_000)}
    nets = {f"{rng.randrange(1, 223)}.{rng.randrange(256)}.{rng.randrange(256)}.0/24" for _ in range(2_000)}
    table, invalid = IpTable[bool].build([(h, True) for h in hosts] + [(n, True) for n in nets])
    assert not invalid
    sample_hosts = list(hosts)[:2000]
    t0 = time.perf_counter()
    for h in sample_hosts:
        assert h in table
    for n in list(nets)[:2000]:
        assert n.replace(".0/24", ".99") in table
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, f"4000 lookups took {elapsed:.3f}s"
    # spot-check negatives against a brute-force oracle
    networks = [ipaddress.ip_network(n) for n in nets]
    for _ in range(200):
        ip = ipaddress.IPv4Address(rng.getrandbits(32))
        expected = str(ip) in hosts or any(ip in net for net in networks)
        assert (ip in table) is expected
