"""Architecture layer remediation: convert findings to recommendations."""

from typing import List

from prompt_hardener.analyze.report import Finding
from prompt_hardener.models import AgentSpec
from prompt_hardener.remediate.report import Recommendation


def remediate_architecture(spec: AgentSpec, findings: List[Finding]) -> List[Recommendation]:
    """Generate architecture-layer recommendations from findings and spec analysis.

    Converts architecture-layer findings to Recommendation objects and adds
    proactive recommendations based on agent type and configuration.
    No LLM calls required.
    """
    recommendations = []

    # Convert existing architecture-layer findings to recommendations
    for f in findings:
        if f.layer != "architecture":
            continue
        recommendations.append(Recommendation(
            severity=f.severity,
            title=f.title,
            description=f.description,
            suggested_change=f.recommendation if f.recommendation else None,
        ))

    # Proactive recommendations based on agent type
    if spec.type in ("agent", "mcp-agent"):
        _add_agent_recommendations(spec, recommendations)

    if spec.type == "mcp-agent":
        _add_mcp_recommendations(spec, recommendations)

    if spec.type == "rag":
        _add_rag_recommendations(spec, recommendations)

    return recommendations


def _add_agent_recommendations(spec: AgentSpec, recommendations: List[Recommendation]) -> None:
    """Add recommendations specific to agent and mcp-agent types."""
    # Check for HITL (human-in-the-loop) controls
    has_escalation = (
        spec.policies is not None
        and spec.policies.escalation_rules is not None
        and len(spec.policies.escalation_rules) > 0
    )
    if not has_escalation:
        recommendations.append(Recommendation(
            severity="high",
            title="Implement human-in-the-loop controls",
            description=(
                "Agent type '%s' can execute tools autonomously but has no "
                "escalation rules requiring human approval for sensitive "
                "operations. Add escalation_rules to enforce HITL for "
                "destructive or high-impact actions." % spec.type
            ),
            suggested_change=(
                "policies:\n"
                "  escalation_rules:\n"
                "    - condition: \"Destructive operation requested\"\n"
                "      action: \"Require human approval\"\n"
                "    - condition: \"Action affects external systems\"\n"
                "      action: \"Escalate to human agent\""
            ),
        ))

    # Check for model separation (eval vs execution)
    # This is a general best practice recommendation
    prompt_lower = spec.system_prompt.lower()
    mentions_separation = any(
        keyword in prompt_lower
        for keyword in ["separate model", "model separation", "dual model", "secondary model"]
    )
    if not mentions_separation and spec.tools and len(spec.tools) > 2:
        recommendations.append(Recommendation(
            severity="low",
            title="Consider model separation for tool execution",
            description=(
                "Agent has %d tools. Consider using separate models for "
                "user-facing conversation and tool execution to reduce the "
                "attack surface of prompt injection." % len(spec.tools)
            ),
        ))


def _add_mcp_recommendations(spec: AgentSpec, recommendations: List[Recommendation]) -> None:
    """Add recommendations specific to MCP agents."""
    if not spec.mcp_servers:
        return

    untrusted_servers = [s for s in spec.mcp_servers if s.trust_level == "untrusted"]
    for server in untrusted_servers:
        if not server.allowed_tools:
            recommendations.append(Recommendation(
                severity="high",
                title="Restrict allowed_tools for untrusted MCP server '%s'" % server.name,
                description=(
                    "Untrusted MCP server '%s' has no allowed_tools restriction. "
                    "Without an explicit allowlist, a compromised server could "
                    "invoke any available tool. Define allowed_tools to limit "
                    "the server's capabilities." % server.name
                ),
                suggested_change=(
                    "mcp_servers:\n"
                    "  - name: %s\n"
                    "    trust_level: untrusted\n"
                    "    allowed_tools: [<limited set of tools>]" % server.name
                ),
            ))

        # Output sanitization recommendation for untrusted MCP servers
        recommendations.append(Recommendation(
            severity="medium",
            title="Sanitize outputs from untrusted MCP server '%s'" % server.name,
            description=(
                "Data returned by untrusted MCP server '%s' should be treated "
                "as potentially malicious. Ensure the system prompt instructs "
                "the agent to validate and sanitize any data received from "
                "this server before using it in responses or tool calls." % server.name
            ),
        ))


def _add_rag_recommendations(spec: AgentSpec, recommendations: List[Recommendation]) -> None:
    """Add recommendations specific to RAG agents."""
    if not spec.data_sources:
        return

    untrusted_sources = [ds for ds in spec.data_sources if ds.trust_level == "untrusted"]
    if untrusted_sources:
        prompt_lower = spec.system_prompt.lower()
        mentions_boundary = any(
            keyword in prompt_lower
            for keyword in ["boundary", "delimiter", "separator", "untrusted", "sanitize"]
        )
        if not mentions_boundary:
            recommendations.append(Recommendation(
                severity="medium",
                title="Add data boundary markers for untrusted sources",
                description=(
                    "RAG agent uses untrusted data sources (%s) but the "
                    "system prompt does not mention data boundaries or "
                    "delimiters. Add explicit instructions to treat "
                    "retrieved content as data, not instructions."
                    % ", ".join(ds.name for ds in untrusted_sources)
                ),
            ))
