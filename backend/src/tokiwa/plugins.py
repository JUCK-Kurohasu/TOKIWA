"""Package auto-discovery used by every extension point (detectors, enrichers, API routes, sources ...).

Importing a package's submodules triggers their ``@register_*`` decorators. A broken module is logged and
skipped instead of taking the whole server down (important while many people work in parallel).
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from types import ModuleType

log = logging.getLogger(__name__)

_loaded: set[str] = set()


def import_submodules(package: str, *, recursive: bool = True, strict: bool = False) -> list[ModuleType]:
    pkg = importlib.import_module(package)
    modules: list[ModuleType] = []
    paths = getattr(pkg, "__path__", None)
    if paths is None:
        return modules
    walker = (
        pkgutil.walk_packages(paths, prefix=f"{package}.")
        if recursive
        else pkgutil.iter_modules(paths, prefix=f"{package}.")
    )
    for info in walker:
        name = info.name
        if name.rsplit(".", 1)[-1].startswith("_"):
            continue
        try:
            modules.append(importlib.import_module(name))
            _loaded.add(name)
        except Exception:
            if strict:
                raise
            log.exception("failed to import plugin module %s (skipped)", name)
    return modules
