"""Structural checks for lab/compose.yaml (the sandbox has no Docker daemon to run it)."""

from __future__ import annotations

from pathlib import Path

import yaml

LAB = Path(__file__).resolve().parents[3] / "lab"


def test_compose_structure() -> None:
    doc = yaml.safe_load((LAB / "compose.yaml").read_text(encoding="utf-8"))
    services = doc["services"]
    assert {"tokiwa-init", "tokiwa", "gate", "victim", "agent", "sim"} <= set(services)
    declared_volumes = set(doc.get("volumes") or {})
    for name, svc in services.items():
        for dep in svc.get("depends_on") or {}:
            assert dep in services, f"{name} depends on unknown service {dep}"
        for vol in svc.get("volumes") or []:
            src = vol.split(":", 1)[0]
            if src.startswith("."):
                # lab/nginx/tokiwa-json.conf is owned by the sensors module; it may land via another branch
                if "nginx/" not in src:
                    assert (LAB / src).exists(), f"{name}: missing {src}"
            else:
                assert src in declared_volumes, f"{name}: undeclared volume {src}"
    assert services["tokiwa"]["build"]["dockerfile"] == "deploy/Dockerfile"
    assert services["gate"]["environment"]["TOKIWA_GATE__UPSTREAM"] == "http://victim:3000"
    # the simulator only ever targets the lab gate
    assert "http://gate:8080" in services["sim"]["command"]
    # no secrets in the compose file: tokens come from the shared volume at runtime
    text = (LAB / "compose.yaml").read_text(encoding="utf-8")
    assert "tkw_" not in text
