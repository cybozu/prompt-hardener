"""Tool/Policy layer rules."""

import re

from prompt_hardener.analyze.report import Finding
from prompt_hardener.analyze.rules import rule

# Tool names that suggest destructive or sensitive operations
_SENSITIVE_TOOL_PATTERNS = [
    r"delete",
    r"remove",
    r"destroy",
    r"drop",
    r"modify",
    r"update",
    r"write",
    r"create",
    r"send",
    r"transfer",
    r"execute",
    r"run",
    r"deploy",
    r"publish",
    r"pay",
    r"refund",
    r"cancel",
]


def _is_sensitive_tool(name):
    # type: (str) -> bool
    lower = name.lower()
    for pattern in _SENSITIVE_TOOL_PATTERNS:
        if re.search(pattern, lower):
            return True
    return False


@rule(
    id="TOOL-001",
    name="High-sensitivity tool without approval",
    layer="tool",
    severity="high",
    types=["agent", "mcp-agent"],
    description="Destructive or sensitive tools lack corresponding escalation rules.",
)
def check_sensitive_tool_approval(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    if not spec.tools:
        return findings

    # Collect escalation conditions as lowered text for matching
    escalation_texts = []
    if spec.policies and spec.policies.escalation_rules:
        for er in spec.policies.escalation_rules:
            escalation_texts.append(er.condition.lower())
            escalation_texts.append(er.action.lower())

    # Also check denied_actions — if a sensitive tool is explicitly denied, it's OK
    denied = set()
    if spec.policies and spec.policies.denied_actions:
        denied = set(a.lower() for a in spec.policies.denied_actions)

    for i, tool in enumerate(spec.tools):
        if not _is_sensitive_tool(tool.name):
            continue
        if tool.name.lower() in denied:
            continue

        # Check if any escalation rule references this tool
        tool_lower = tool.name.lower()
        has_escalation = any(
            tool_lower in text or any(word in text for word in tool_lower.split("_"))
            for text in escalation_texts
        )
        if has_escalation:
            continue

        findings.append(
            Finding(
                id="",
                rule_id="TOOL-001",
                title="Sensitive tool '%s' without escalation rule" % tool.name,
                severity="high",
                layer="tool",
                description=(
                    "Tool '%s' appears to perform a sensitive or destructive operation "
                    "but has no corresponding escalation rule requiring human approval."
                    % tool.name
                ),
                evidence=[
                    "tools[%d].name = '%s' matches sensitive pattern" % (i, tool.name),
                    "No escalation_rule references this tool",
                ],
                spec_path="tools[%d]" % i,
                recommendation=(
                    "Add an escalation rule for '%s' that requires human approval "
                    "before execution. Example: condition: 'User requests %s', "
                    "action: 'Require explicit confirmation before proceeding'."
                    % (tool.name, tool.name.replace("_", " "))
                ),
            )
        )

    return findings


@rule(
    id="TOOL-002",
    name="Overly broad tool permissions",
    layer="tool",
    severity="medium",
    types=["agent", "mcp-agent"],
    description="Tools are defined but allowed_actions is not set, implying all tools are permitted.",
)
def check_broad_tool_permissions(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    if not spec.tools:
        return findings

    has_allowed = (
        spec.policies is not None
        and spec.policies.allowed_actions is not None
        and len(spec.policies.allowed_actions) > 0
    )

    if has_allowed:
        return findings

    tool_names = [t.name for t in spec.tools]
    findings.append(
        Finding(
            id="",
            rule_id="TOOL-002",
            title="No allowed_actions defined for %d tools" % len(spec.tools),
            severity="medium",
            layer="tool",
            description=(
                "%d tools are defined but policies.allowed_actions is not set. "
                "This implicitly allows all tools without an explicit allowlist."
                % len(spec.tools)
            ),
            evidence=[
                "tools contains %d definitions: %s"
                % (len(tool_names), ", ".join(tool_names)),
                "policies.allowed_actions is not defined",
            ],
            spec_path="policies.allowed_actions",
            recommendation=(
                "Define an explicit allowed_actions list in policies to restrict which "
                "tools the agent can use. This follows the principle of least privilege."
            ),
        )
    )

    return findings
