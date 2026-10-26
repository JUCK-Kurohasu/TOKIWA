"""In-memory Sigma rule engine for TOKIWA events.

Public API (other modules import from here, not from the submodules):

* :func:`validate_rule` ``(content) -> (valid, errors, title)`` - used by the rules API and by the intel advisor
  to vet LLM-proposed rules before storing them as ``status=proposed``;
* :func:`parse_rule` - YAML -> compiled :class:`SigmaRule` (raises :class:`SigmaError`);
* :func:`get_rule_store` - the live rule set; call ``await get_rule_store().reload()`` after changing the
  ``rules`` table so the change takes effect immediately.

See docs/detection/sigma.md for the supported Sigma subset and the field mapping.
"""

from __future__ import annotations

from tokiwa.detect.sigma.evaluator import MatchResult, SigmaRule
from tokiwa.detect.sigma.loader import LoadedRule, SigmaRuleStore, get_rule_store, sync_builtin_rules
from tokiwa.detect.sigma.mapping import mitre_from_tags, rule_meta
from tokiwa.detect.sigma.parser import SigmaError, parse_rule, validate_rule

__all__ = [
    "LoadedRule",
    "MatchResult",
    "SigmaError",
    "SigmaRule",
    "SigmaRuleStore",
    "get_rule_store",
    "mitre_from_tags",
    "parse_rule",
    "rule_meta",
    "sync_builtin_rules",
    "validate_rule",
]
