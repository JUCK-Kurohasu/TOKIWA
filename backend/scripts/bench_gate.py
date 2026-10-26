"""Quick throughput / latency benchmark for TOKIWA Gate (lab use, localhost only).

    cd backend
    uv run python scripts/bench_gate.py                       # spawn backend + gate, 10 s, 32 workers
    uv run python scripts/bench_gate.py --inject --post-bytes 2048
    uv run python scripts/bench_gate.py --direct              # baseline: hit the upstream without the gate
    uv run python scripts/bench_gate.py --gate-url http://127.0.0.1:8080 --path /   # an already running gate

What gets spawned (unless --gate-url): one "backend" process playing both the protected upstream app and a fake
TOKIWA server (accepts /api/v1/ingest/events, serves /api/v1/gate/policy), plus the real ``tokiwa gate run``
entrypoint in its own process. The load generator runs in this process (httpx, asyncio), so on small machines it
competes for CPU with the gate; treat results as a lower bound.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import multiprocessing as mp
import os
import socket
import statistics
import subprocess
import sys
import time
from collections import Counter
from typing import Any

import httpx

TOKEN = "tkw_bench_token_not_secret"


# ----------------------------------------------------------------------------------------------- backend
def _backend_main(port: int, inject: bool) -> None:
    """Upstream app + fake TOKIWA server in one process."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse, Response
    from starlette.routing import Route

    state = {"events": 0, "batches": 0}
    html = (
        "<!DOCTYPE html><html><head><title>bench</title></head><body>"
        + "<p>lorem ipsum</p>" * 50
        + "</body></html>"
    )
    policy = {
        "version": "bench-1",
        "generated_at": "2026-01-01T00:00:00Z",
        "blocked": [
            f"198.18.{i // 256}.{i % 256}" for i in range(2000)
        ],  # realistic table size, not matching
        "rate_limited": {},
        "tarpit": {},
        "deceive": [],
        "decoys": [{"asset_id": "bench", "kind": "decoy_path", "path": "/.env", "body": "X=1"}],
        "html_injection": "<div hidden>bench canary</div>" if inject else None,
    }

    async def page(request: Request) -> Response:
        await request.body()
        return HTMLResponse(html)

    async def api(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"ok": True, "received": len(body)})

    async def ingest(request: Request) -> Response:
        data = json.loads(await request.body())
        state["events"] += len(data["events"])
        state["batches"] += 1
        return JSONResponse({"accepted": len(data["events"]), "alerts": 0, "alert_ids": []})

    async def gate_policy(request: Request) -> Response:
        return JSONResponse(policy)

    async def stats(request: Request) -> Response:
        return JSONResponse(state)

    app = Starlette(
        routes=[
            Route("/api/v1/ingest/events", ingest, methods=["POST"]),
            Route("/api/v1/gate/policy", gate_policy),
            Route("/__bench/stats", stats),
            Route("/api/{rest:path}", api, methods=["GET", "POST"]),
            Route("/{rest:path}", page, methods=["GET", "POST"]),
        ]
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_ready(url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    with httpx.Client(trust_env=False) as c:
        while time.monotonic() < deadline:
            try:
                if c.get(url, timeout=1.0).status_code < 500:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
    raise RuntimeError(f"{url} did not become ready")


# ---------------------------------------------------------------------------------------------- load gen
async def _load(url: str, path: str, duration: float, concurrency: int, post_bytes: int) -> dict[str, Any]:
    latencies: list[float] = []
    statuses: Counter[str] = Counter()
    body = (b"q=" + b"A" * max(0, post_bytes - 2)) if post_bytes else None
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    stop_at = time.monotonic() + duration

    async with httpx.AsyncClient(base_url=url, trust_env=False, limits=limits, timeout=30.0) as client:

        async def worker() -> None:
            while time.monotonic() < stop_at:
                t0 = time.perf_counter()
                try:
                    if body is None:
                        r = await client.get(path, headers={"User-Agent": "bench/1.0"})
                    else:
                        r = await client.post(
                            path,
                            content=body,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "User-Agent": "bench/1.0",
                            },
                        )
                    await r.aread()
                    statuses[str(r.status_code)] += 1
                except httpx.HTTPError as exc:
                    statuses[type(exc).__name__] += 1
                latencies.append((time.perf_counter() - t0) * 1000.0)

        started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        elapsed = time.perf_counter() - started

    latencies.sort()

    def pct(p: float) -> float:
        return latencies[min(len(latencies) - 1, int(len(latencies) * p))] if latencies else 0.0

    return {
        "requests": len(latencies),
        "seconds": round(elapsed, 2),
        "rps": round(len(latencies) / elapsed, 1) if elapsed else 0.0,
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 2) if latencies else 0.0,
            "p50": round(pct(0.50), 2),
            "p95": round(pct(0.95), 2),
            "p99": round(pct(0.99), 2),
            "max": round(latencies[-1], 2) if latencies else 0.0,
        },
        "statuses": dict(statuses),
    }


async def _measure(args: argparse.Namespace, target: str) -> dict[str, Any]:
    if args.warmup > 0:
        await _load(target, args.path, args.warmup, min(4, args.concurrency), args.post_bytes)
    return await _load(target, args.path, args.duration, args.concurrency, args.post_bytes)


def _run(args: argparse.Namespace) -> dict[str, Any]:
    procs: list[Any] = []
    result: dict[str, Any] = {"config": vars(args).copy()}
    backend_url: str | None = None
    try:
        if args.gate_url:
            target = args.gate_url
        else:
            backend_port, gate_port = _free_port(), _free_port()
            backend_url = f"http://127.0.0.1:{backend_port}"
            ctx = mp.get_context("spawn")
            backend = ctx.Process(target=_backend_main, args=(backend_port, args.inject), daemon=True)
            backend.start()
            procs.append(backend)
            _wait_ready(f"{backend_url}/__bench/stats")
            if args.direct:
                target = backend_url
            else:
                env = {
                    **os.environ,
                    "TOKIWA_CONFIG": os.devnull,
                    "TOKIWA_LOG_LEVEL": "WARNING",
                    "TOKIWA_GATE__INGEST_TOKEN": TOKEN,
                }
                cmd = [
                    sys.executable,
                    "-m",
                    "tokiwa.cli",
                    "gate",
                    "run",
                    "--upstream",
                    backend_url,
                    "--listen",
                    f"127.0.0.1:{gate_port}",
                    "--server",
                    backend_url,
                    "--policy-refresh",
                    "2",
                ]
                procs.append(subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL))  # noqa: S603 - fixed argv
                target = f"http://127.0.0.1:{gate_port}"
                _wait_ready(f"{target}/__tokiwa/health")

        result["load"] = asyncio.run(_measure(args, target))

        if backend_url and not args.direct:
            time.sleep(2.5)  # let the shipper flush the last partial batch
            with httpx.Client(trust_env=False) as c:
                result["gate_health"] = c.get(f"{target}/__tokiwa/health").json()
                result["server_received"] = c.get(f"{backend_url}/__bench/stats").json()
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            if isinstance(p, subprocess.Popen):
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
            else:
                p.join(timeout=5)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--duration", type=float, default=10.0, help="seconds of measured load")
    parser.add_argument("--warmup", type=float, default=1.0, help="seconds of unmeasured warm-up")
    parser.add_argument("--concurrency", type=int, default=32, help="concurrent client workers")
    parser.add_argument("--path", default="/", help="request path (/ = HTML page, /api/x = JSON)")
    parser.add_argument(
        "--post-bytes", type=int, default=0, help="POST a form body of this size instead of GET"
    )
    parser.add_argument("--inject", action="store_true", help="enable html_injection in the served policy")
    parser.add_argument("--direct", action="store_true", help="bypass the gate (upstream baseline)")
    parser.add_argument("--gate-url", default=None, help="benchmark an already running gate instead")
    parser.add_argument("--json", action="store_true", help="print raw JSON only")
    args = parser.parse_args()

    result = _run(args)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    load = result["load"]
    mode = "direct (no gate)" if args.direct else (args.gate_url or "spawned gate")
    print(f"target: {mode}  path={args.path}  concurrency={args.concurrency}  post_bytes={args.post_bytes}")
    print(f"requests: {load['requests']} in {load['seconds']} s  ->  {load['rps']} req/s")
    lat = load["latency_ms"]
    print(
        f"latency ms: mean {lat['mean']}  p50 {lat['p50']}  p95 {lat['p95']}  p99 {lat['p99']}  max {lat['max']}"
    )
    print(f"statuses: {load['statuses']}")
    if "server_received" in result:
        shipper = result["gate_health"].get("shipper", {})
        print(
            f"events shipped: {result['server_received']['events']} in {result['server_received']['batches']} batches"
            f"  (gate queue {shipper.get('queued')}, dropped {shipper.get('dropped_overflow')})"
        )


if __name__ == "__main__":
    main()
