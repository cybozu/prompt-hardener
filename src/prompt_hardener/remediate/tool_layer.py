"""Tool layer remediation: convert findings to recommendations."""

from typing import List

from prompt_hardener.analyze.report import Finding
from prompt_hardener.models import AgentSpec
from prompt_hardener.remediate.report import Recommendation

# Tool names that are commonly dangerous when unrestricted
_DANGEROUS_TOOL_PATTERNS = [
    "delete", "remove", "drop", "destroy",
    "transfer", "send", "execute", "exec", "run",
    "write", "modify", "update", "patch",
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
        recommendations.append(Recommendation(
            severity=f.severity,
            title=f.title,
            description=f.description,
            suggested_change=f.recommendation if f.recommendation else None,
        ))

    # Proactive recommendations based on spec analysis
    if spec.policies is None:
        recommendations.append(Recommendation(
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
                "    - \"<boundary description>\""
            ),
        ))
    else:
        # Check for missing allowed_actions
        if spec.tools and not spec.policies.allowed_actions:
            recommendations.append(Recommendation(
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
            ))

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
                recommendations.append(Recommendation(
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
                ))

        # Check for missing escalation_rules when tools exist
        if spec.tools and not spec.policies.escalation_rules:
            recommendations.append(Recommendation(
                severity="low",
                title="Add escalation rules for sensitive tool calls",
                description=(
                    "No escalation_rules are defined. Consider adding rules that "
                    "require human approval for destructive or high-impact operations."
                ),
                suggested_change=(
                    "policies:\n"
                    "  escalation_rules:\n"
                    "    - condition: \"User requests destructive action\"\n"
                    "      action: \"Require human confirmation\""
                ),
            ))

    return recommendations
