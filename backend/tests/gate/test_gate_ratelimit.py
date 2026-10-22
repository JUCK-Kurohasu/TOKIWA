from __future__ import annotations

from gate_helpers import FakeTime

from tokiwa.gate.ratelimit import TokenBucketLimiter


def test_burst_then_429_then_refill() -> None:
    t = FakeTime()
    limiter = TokenBucketLimiter(clock=t.clock)
    assert [limiter.allow("1.2.3.4", 3)[0] for _ in range(3)] == [True, True, True]
    allowed, retry_after = limiter.allow("1.2.3.4", 3)
    assert not allowed
    assert retry_after == 20  # 3/min -> one token every 20 s
    t.advance(20)
    assert limiter.allow("1.2.3.4", 3) == (True, 0.0)
    assert limiter.allow("1.2.3.4", 3)[0] is False


def test_buckets_are_per_client() -> None:
    t = FakeTime()
    limiter = TokenBucketLimiter(clock=t.clock)
    assert limiter.allow("a", 1)[0]
    assert not limiter.allow("a", 1)[0]
    assert limiter.allow("b", 1)[0]


def test_zero_limit_denies() -> None:
    limiter = TokenBucketLimiter()
    assert limiter.allow("a", 0) == (False, 60.0)


def test_limit_change_rescales_bucket() -> None:
    t = FakeTime()
    limiter = TokenBucketLimiter(clock=t.clock)
    for _ in range(10):
        assert limiter.allow("a", 10)[0]
    # bucket empty at 10/min; policy tightens to 2/min: still empty, must wait 30 s for a token
    allowed, retry = limiter.allow("a", 2)
    assert not allowed and retry == 30
    t.advance(30)
    assert limiter.allow("a", 2)[0]


def test_lru_bound() -> None:
    limiter = TokenBucketLimiter(max_keys=100)
    for i in range(1000):
        limiter.allow(f"10.0.{i // 256}.{i % 256}", 5)
    assert len(limiter) == 100
    limiter.reset()
    assert len(limiter) == 0
