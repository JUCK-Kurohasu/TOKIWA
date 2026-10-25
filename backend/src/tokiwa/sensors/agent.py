"""TOKIWA Agent: wires the host sensor and the log sources to the shipper (``tokiwa agent run``)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time
from pathlib import Path

from tokiwa.config import AgentSettings
from tokiwa.schemas.events import Event, HostInfo
from tokiwa.sensors.caddy import CaddyJsonParser
from tokiwa.sensors.host import HostSensor
from tokiwa.sensors.logtail import FileTailer, LogSource, StartAt
from tokiwa.sensors.nginx import NginxJsonParser
from tokiwa.sensors.normalize import ParseContext
from tokiwa.sensors.shipper import Shipper
from tokiwa.sensors.suricata import SuricataEveParser
from tokiwa.sensors.zeek import SUPPORTED as ZEEK_LOGS
from tokiwa.sensors.zeek import ZeekParser, log_type_from_name

log = logging.getLogger(__name__)


def build_sources(cfg: AgentSettings, ctx: ParseContext, start_at: StartAt) -> list[LogSource]:
    """One :class:`LogSource` per configured file. Missing files are fine: they are picked up once created."""
    sources: list[LogSource] = []

    def add(path: Path, parser: NginxJsonParser | CaddyJsonParser | SuricataEveParser | ZeekParser) -> None:
        sources.append(LogSource(FileTailer(path, start_at=start_at), parser))

    for p in cfg.nginx_json_logs:
        add(Path(p), NginxJsonParser(ctx))
    for p in cfg.caddy_json_logs:
        add(Path(p), CaddyJsonParser(ctx))
    for p in cfg.suricata_eve_logs:
        add(Path(p), SuricataEveParser(ctx))
    for d in cfg.zeek_log_dirs:
        d = Path(d)
        single = log_type_from_name(d.name) if d.suffix else None
        if single is not None:  # a single Zeek log file was given instead of a directory
            add(d, ZeekParser(ctx, single))
            continue
        for name in ZEEK_LOGS:
            add(d / f"{name}.log", ZeekParser(ctx, name))
    return sources


class Agent:
    def __init__(
        self,
        cfg: AgentSettings,
        *,
        start_at: StartAt | None = None,
        host_sensor: HostSensor | None = None,
        sources: list[LogSource] | None = None,
        shipper: Shipper | None = None,
    ) -> None:
        self.cfg = cfg
        hostname = socket.gethostname()
        self.sensor_id = cfg.sensor_id or hostname
        if host_sensor is None and cfg.host_sensor:
            host_sensor = HostSensor(
                sensor_id=self.sensor_id,
                hostname=hostname,
                collect_connections=cfg.connections,
                max_connections=cfg.max_connections_per_cycle,
                ignore_ephemeral_udp=cfg.udp_ignore_ephemeral,
            )
        self.host_sensor = host_sensor
        ctx = ParseContext(sensor_id=self.sensor_id, host=HostInfo(name=hostname))
        self.sources = (
            sources if sources is not None else build_sources(cfg, ctx, start_at or cfg.log_start_at)
        )
        self._shipper = shipper

    @property
    def shipper(self) -> Shipper:
        if self._shipper is None:
            token = self.cfg.ingest_token.get_secret_value() if self.cfg.ingest_token else None
            self._shipper = Shipper(
                self.cfg.server_url,
                token,
                batch_size=self.cfg.batch_size,
                max_buffer=self.cfg.max_buffer_events,
                max_retries=self.cfg.max_retries,
                verify=self.cfg.verify_tls,
            )
        return self._shipper

    async def collect(self, *, host: bool = True) -> list[Event]:
        events: list[Event] = []
        if host and self.host_sensor is not None:
            try:
                events.extend(await self.host_sensor.poll())
            except Exception:
                log.exception("host sensor failed")
        for src in self.sources:
            try:
                events.extend(await src.poll())
            except Exception:
                log.exception("log source %s failed", src.name)
        return events

    async def run(self, stop: asyncio.Event | None = None) -> None:
        stop = stop or asyncio.Event()
        shipper = self.shipper
        interval = max(0.5, self.cfg.interval_seconds)
        tick = min(interval, max(0.1, self.cfg.log_poll_seconds)) if self.sources else interval
        log.info(
            "agent %s started: host_sensor=%s, %d log sources, server=%s",
            self.sensor_id,
            self.host_sensor is not None,
            len(self.sources),
            self.cfg.server_url,
        )
        next_host = 0.0
        try:
            while not stop.is_set():
                now = time.monotonic()
                do_host = self.host_sensor is not None and now >= next_host
                if do_host:
                    next_host = now + interval
                events = await self.collect(host=do_host)
                if events:
                    shipper.submit(events)
                await shipper.flush()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=tick)
        finally:
            try:
                await shipper.flush(force=True)
            except Exception:
                log.exception("final flush failed")
            await shipper.aclose()
            for src in self.sources:
                src.close()
            log.info(
                "agent stopped: sent=%d pending=%d dropped=%d", shipper.sent, shipper.pending, shipper.dropped
            )
