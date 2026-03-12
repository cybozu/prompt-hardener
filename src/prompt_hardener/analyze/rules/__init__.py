"""Rule registry for static analysis."""

from dataclasses import dataclass
from typing import List


@dataclass
class RuleMeta:
    id: str
    name: str
    layer: str  # "prompt" | "tool" | "architecture"
    severity: str  # "low" | "medium" | "high" | "critical"
    applicable_types: List[str]
    description: str = ""


_RULE_REGISTRY = []  # type: List


def rule(id, name, layer, severity, types, description=""):
    """Decorator to register a finding rule.

    Each decorated function must have signature (AgentSpec) -> List[Finding].
    """

    def decorator(fn):
        fn.meta = RuleMeta(
            id=id,
            name=name,
            layer=layer,
            severity=severity,
            applicable_types=list(types),
            description=description,
        )
        _RULE_REGISTRY.append(fn)
        return fn

    return decorator


def get_rules(agent_type=None, layers=None):
    # type: (Optional[str], Optional[List[str]]) -> list
    """Return rules filtered by agent type and/or layers."""
    result = []
    for fn in _RULE_REGISTRY:
        meta = fn.meta
        if agent_type and agent_type not in meta.applicable_types:
            continue
        if layers and meta.layer not in layers:
            continue
        result.append(fn)
    return result


def _ensure_rules_loaded():
    """Import rule modules so decorators execute and populate the registry."""
    import prompt_hardener.analyze.rules.prompt_rules  # noqa: F401
    import prompt_hardener.analyze.rules.tool_rules  # noqa: F401
    import prompt_hardener.analyze.rules.arch_rules  # noqa: F401
