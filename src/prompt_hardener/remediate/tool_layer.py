"""Tool layer remediation: convert findings to recommendations."""

from typing import List

from prompt_hardener.analyze.report import Finding
from prompt_hardener.models import AgentSpec
from prompt_hardener.remediate.report import Recommendation

# Tool names that are commonly dangerous when unrestricted
_DANGEROUS_TOOL_PATTERNS = [
    "delete",
    "remove",
    "drop",
    "destroy",
    "transfer",
    "send",
    "execute",
    "exec",
    "run",
    "write",
    "modify",
    "update",
    "patch",
]


def remediate_tool(spec: AgentSpec, findings: List[Finding]) -> List[Recommendation]:
    """Generate tool-layer recommendations from findings and spec analysis.

    Converts tool-layer findings to Recommendation objects and adds
    proactive recommendations based on the spec configuration.
    No LLM calls required.
    """
    recommendations = []

    # Convert existing tool-layer findings to recommendations
    for f in findings:
        if f.layer != "tool":
            continue
        recommendations.append(
            Recommendation(
                severity=f.severity,
                title=f.title,
                description=f.description,
                suggested_change=f.recommendation if f.recommendation else None,
            )
        )

    # Proactive recommendations based on spec analysis
    if spec.policies is None:
        recommendations.append(
            Recommendation(
                severity="high",
                title="Define tool usage policies",
                description=(
                    "No policies section is defined. Add a policies section with "
                    "allowed_actions, denied_actions, and data_boundaries to "
                    "restrict tool usage."
                ),
                suggested_change=(
                    "policies:\n"
                    "  allowed_actions: [<list of permitted tools>]\n"
                    "  denied_actions: [<list of forbidden operations>]\n"
                    "  data_boundaries:\n"
                    '    - "<boundary description>"'
                ),
            )
        )
    else:
        # Check for missing allowed_actions
        if spec.tools and not spec.policies.allowed_actions:
            recommendations.append(
                Recommendation(
                    severity="medium",
                    title="Add allowed_actions allowlist",
                    description=(
                        "Tools are defined but no allowed_actions list restricts which "
                        "tools the agent may call. Add an explicit allowlist to prevent "
                        "unintended tool usage."
                    ),
                    suggested_change=(
                        "policies:\n"
                        "  allowed_actions:\n"
                        + "".join("    - %s\n" % t.name for t in spec.tools)
                    ),
                )
            )

        # Check for missing denied_actions
        if spec.tools and not spec.policies.denied_actions:
            # Check if any tools look dangerous
            dangerous = []
            for t in spec.tools:
                name_lower = t.name.lower()
                desc_lower = (t.description or "").lower()
                for pattern in _DANGEROUS_TOOL_PATTERNS:
                    if pattern in name_lower or pattern in desc_lower:
                        dangerous.append(t.name)
                        break
            if dangerous:
                recommendations.append(
                    Recommendation(
                        severity="medium",
                        title="Add denied_actions for sensitive operations",
                        description=(
                            "No denied_actions list is defined. The following tools "
                            "appear to perform sensitive operations: %s. "
                            "Consider adding a denied_actions list to explicitly "
                            "block dangerous operations." % ", ".join(dangerous)
                        ),
                        suggested_change=(
                            "policies:\n"
                            "  denied_actions:\n"
                            "    - <dangerous_operation_name>"
                        ),
                    )
                )

        # Check for missing escalation_rules when tools exist
        if spec.tools and not spec.policies.escalation_rules:
            recommendations.append(
                Recommendation(
                    severity="low",
                    title="Add escalation rules for sensitive tool calls",
                    description=(
                        "No escalation_rules are defined. Consider adding rules that "
                        "require human approval for destructive or high-impact operations."
                    ),
                    suggested_change=(
                        "policies:\n"
                        "  escalation_rules:\n"
                        '    - condition: "User requests destructive action"\n'
                        '      action: "Require human confirmation"'
                    ),
                )
            )

    # Proactive recommendations based on effect/impact/execution_identity
    if spec.tools:
        _add_effect_based_recommendations(spec, recommendations)

    return recommendations


def _add_effect_based_recommendations(
    spec: AgentSpec, recommendations: List[Recommendation]
) -> None:
    """Add recommendations based on tool effect/impact/execution_identity annotations."""
    unannotated = [t for t in spec.tools if t.effect is None and t.impact is None]
    if unannotated and len(unannotated) < len(spec.tools):
        # Some tools are annotated, others aren't — recommend completing annotations
        recommendations.append(
            Recommendation(
                severity="low",
                title="Complete tool effect/impact annotations",
                description=(
                    "Some tools have effect/impact annotations but %d tool(s) do not: %s. "
                    "Annotating all tools enables more accurate security analysis."
                    % (
                        len(unannotated),
                        ", ".join(t.name for t in unannotated),
                    )
                ),
                suggested_change=(
                    "tools:\n"
                    "  - name: <tool_name>\n"
                    "    effect: read|write|delete|external_send\n"
                    "    impact: low|medium|high"
                ),
            )
        )

    # Recommend HITL for external_send tools
    external_send_tools = [t for t in spec.tools if t.effect == "external_send"]
    if external_send_tools:
        has_escalation = (
            spec.policies is not None
            and spec.policies.escalation_rules is not None
            and len(spec.policies.escalation_rules) > 0
        )
        if not has_escalation:
            recommendations.append(
                Recommendation(
                    severity="high",
                    title="Add escalation rules for external_send tools",
                    description=(
                        "Tools with effect 'external_send' (%s) can send data to "
                        "external systems. Without escalation rules requiring human "
                        "approval, a prompt injection could exfiltrate data."
                        % ", ".join(t.name for t in external_send_tools)
                    ),
                    suggested_change=(
                        "policies:\n"
                        "  escalation_rules:\n"
                        '    - condition: "External send operation requested"\n'
                        '      action: "Require human approval"'
                    ),
                )
            )

    # Recommend restrictions for service-identity tools
    service_tools = [t for t in spec.tools if t.execution_identity == "service"]
    if service_tools:
        has_restrictions = (
            spec.policies is not None
            and (spec.policies.denied_actions or spec.policies.escalation_rules)
        )
        if not has_restrictions:
            recommendations.append(
                Recommendation(
                    severity="medium",
                    title="Add restrictions for service-identity tools",
                    description=(
                        "Tools with execution_identity 'service' (%s) run with "
                        "elevated privileges. Add denied_actions or escalation_rules "
                        "to limit their scope."
                        % ", ".join(t.name for t in service_tools)
                    ),
                    suggested_change=(
                        "policies:\n"
                        "  escalation_rules:\n"
                        '    - condition: "Service-level tool invocation"\n'
                        '      action: "Require human approval"'
                    ),
                )
            )
