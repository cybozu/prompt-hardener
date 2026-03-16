"""Normalize AgentSpec into attack-path-friendly surfaces."""

import re

from prompt_hardener.analyze.attack_paths.models import (
    NormalizedControls,
    NormalizedDataSource,
    NormalizedMcpServer,
    NormalizedSpec,
    NormalizedTool,
)
from prompt_hardener.analyze.rules.arch_rules import (
    _BUDGET_PATTERNS,
    _MEMORY_PROTECTION_PATTERNS,
    _TENANT_ISOLATION_PATTERNS,
    _TOOL_RESULT_PATTERNS,
)
from prompt_hardener.analyze.rules.prompt_rules import (
    _UNTRUSTED_INPUT_PATTERNS,
    _has_pattern,
)
from prompt_hardener.analyze.rules.tool_rules import (
    _is_dangerous_tool,
    _is_egress_capable_tool,
    _is_sensitive_tool,
)


_RETRIEVED_CONTENT_PATTERNS = [
    r"retrieved\s+content\s+.*untrusted",
    r"treat\s+retrieved\s+content\s+as\s+untrusted",
    r"treat\s+documents?\s+as\s+untrusted",
    r"do\s+not\s+trust\s+retrieved\s+content",
    r"do\s+not\s+follow\s+instructions?\s+in\s+retrieved\s+content",
    r"ignore\s+instructions?\s+from\s+context",
    r"search\s+results?\s+.*untrusted",
]


def _contains_pattern(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


def _controls_from_spec(spec):
    prompt_text = (spec.system_prompt or "").lower()
    data_boundaries = spec.policies.data_boundaries if spec.policies else None
    data_boundaries_text = " ".join(data_boundaries or []).lower()
    search_text = ("%s %s" % (prompt_text, data_boundaries_text)).strip()

    escalation_texts = []
    if spec.policies and spec.policies.escalation_rules:
        for rule in spec.policies.escalation_rules:
            escalation_texts.append(rule.condition.lower())
            escalation_texts.append(rule.action.lower())

    denied_actions = []
    if spec.policies and spec.policies.denied_actions:
        denied_actions = [action.lower() for action in spec.policies.denied_actions]

    has_budget_limits = False
    if spec.policies:
        has_budget_limits = any(
            (
                spec.policies.max_tool_calls is not None,
                spec.policies.max_steps is not None,
                bool(spec.policies.rate_limits),
                spec.policies.cost_budget is not None,
            )
        )
    if not has_budget_limits:
        has_budget_limits = _contains_pattern(search_text, _BUDGET_PATTERNS)

    return NormalizedControls(
        has_user_input_distrust=_has_pattern(prompt_text, _UNTRUSTED_INPUT_PATTERNS),
        has_retrieved_content_distrust=_contains_pattern(
            search_text, _RETRIEVED_CONTENT_PATTERNS
        ),
        has_tool_output_distrust=_contains_pattern(prompt_text, _TOOL_RESULT_PATTERNS),
        has_tenant_isolation=_contains_pattern(search_text, _TENANT_ISOLATION_PATTERNS),
        has_budget_limits=has_budget_limits,
        has_memory_protection=_contains_pattern(
            search_text, _MEMORY_PROTECTION_PATTERNS
        ),
        data_boundaries_text=data_boundaries_text,
        prompt_text=prompt_text,
        escalation_texts=escalation_texts,
        denied_actions=denied_actions,
    )


def normalize_spec(spec):
    # type: (AgentSpec) -> NormalizedSpec
    tools = []
    for tool in spec.tools or []:
        effect = getattr(tool, "effect", None) or "unknown"
        impact = getattr(tool, "impact", None) or "unknown"
        execution_identity = getattr(tool, "execution_identity", None) or "unknown"
        tools.append(
            NormalizedTool(
                name=tool.name,
                description=tool.description,
                effect=effect,
                impact=impact,
                execution_identity=execution_identity,
                source=getattr(tool, "source", None) or "unknown",
                is_sensitive=_is_sensitive_tool(tool),
                can_egress=_is_egress_capable_tool(tool),
                can_modify_state=effect in ("write", "delete"),
                has_service_identity=execution_identity == "service",
                is_high_impact=impact == "high",
                can_read_data=effect == "read",
                can_persist_state=("memory" in tool.name.lower())
                or ("remember" in tool.name.lower())
                or ("store" in tool.name.lower()),
                is_dangerous=_is_dangerous_tool(tool),
            )
        )

    data_sources = []
    for data_source in spec.data_sources or []:
        sensitivity = getattr(data_source, "sensitivity", None) or "unknown"
        data_sources.append(
            NormalizedDataSource(
                name=data_source.name,
                type=data_source.type,
                trust_level=data_source.trust_level,
                sensitivity=sensitivity,
                is_untrusted=data_source.trust_level in ("untrusted", "unknown"),
                is_confidential=sensitivity == "confidential",
                is_internal=sensitivity == "internal",
            )
        )

    mcp_servers = []
    for server in spec.mcp_servers or []:
        allowed_tools = list(server.allowed_tools or [])
        source = getattr(server, "source", None) or "unknown"
        mcp_servers.append(
            NormalizedMcpServer(
                name=server.name,
                trust_level=server.trust_level,
                source=source,
                allowed_tools=allowed_tools,
                is_untrusted=server.trust_level in ("untrusted", "unknown"),
                is_third_party=source == "third_party",
                has_tool_restrictions=bool(allowed_tools),
            )
        )

    return NormalizedSpec(
        agent_type=spec.type,
        tools=tools,
        data_sources=data_sources,
        mcp_servers=mcp_servers,
        controls=_controls_from_spec(spec),
        has_persistent_memory=getattr(spec, "has_persistent_memory", None) == "true",
        scope=getattr(spec, "scope", None) or "unknown",
        has_user_message_entrypoint=True,
    )
