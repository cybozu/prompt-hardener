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


def _is_sensitive_tool(tool):
    # type: (Union[str, ToolDef]) -> bool
    """Check if a tool is sensitive based on its name pattern or effect annotation."""
    if isinstance(tool, str):
        name = tool
        effect = None
    else:
        name = tool.name
        effect = getattr(tool, "effect", None)

    # Effect-based detection takes precedence
    if effect in ("write", "delete", "external_send"):
        return True

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
        if not _is_sensitive_tool(tool):
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


def _tool_covered_by_escalation(tool_name, escalation_rules):
    # type: (str, list) -> bool
    """Check if a tool is referenced in any escalation rule."""
    if not escalation_rules:
        return False
    tool_lower = tool_name.lower()
    for er in escalation_rules:
        text = (er.condition + " " + er.action).lower()
        if tool_lower in text or any(word in text for word in tool_lower.split("_")):
            return True
    return False


@rule(
    id="TOOL-003",
    name="High-impact tool without escalation coverage",
    layer="tool",
    severity="critical",
    types=["agent", "mcp-agent"],
    description="Tool explicitly marked as high-impact lacks escalation rule coverage.",
)
def check_high_impact_tool_escalation(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    if not spec.tools:
        return findings

    escalation_rules = []
    if spec.policies and spec.policies.escalation_rules:
        escalation_rules = spec.policies.escalation_rules

    denied = set()
    if spec.policies and spec.policies.denied_actions:
        denied = set(a.lower() for a in spec.policies.denied_actions)

    for i, tool in enumerate(spec.tools):
        if getattr(tool, "impact", None) != "high":
            continue
        if tool.name.lower() in denied:
            continue
        if _tool_covered_by_escalation(tool.name, escalation_rules):
            continue

        findings.append(
            Finding(
                id="",
                rule_id="TOOL-003",
                title="High-impact tool '%s' without escalation coverage" % tool.name,
                severity="critical",
                layer="tool",
                description=(
                    "Tool '%s' is marked as impact: high but is not covered by any "
                    "escalation rule. High-impact tools should require human approval."
                    % tool.name
                ),
                evidence=[
                    "tools[%d].impact = 'high'" % i,
                    "No escalation_rule references '%s'" % tool.name,
                ],
                spec_path="tools[%d]" % i,
                recommendation=(
                    "Add an escalation rule that covers '%s'. "
                    "Example: condition: 'User requests %s', "
                    "action: 'Require human approval before execution'."
                    % (tool.name, tool.name.replace("_", " "))
                ),
            )
        )

    return findings


@rule(
    id="TOOL-004",
    name="Privileged execution identity without restrictions",
    layer="tool",
    severity="high",
    types=["agent", "mcp-agent"],
    description="Tool executes as service identity but has no restriction in denied_actions or escalation_rules.",
)
def check_privileged_identity(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    if not spec.tools:
        return findings

    denied = set()
    if spec.policies and spec.policies.denied_actions:
        denied = set(a.lower() for a in spec.policies.denied_actions)

    escalation_rules = []
    if spec.policies and spec.policies.escalation_rules:
        escalation_rules = spec.policies.escalation_rules

    for i, tool in enumerate(spec.tools):
        if getattr(tool, "execution_identity", None) != "service":
            continue
        if tool.name.lower() in denied:
            continue
        if _tool_covered_by_escalation(tool.name, escalation_rules):
            continue

        findings.append(
            Finding(
                id="",
                rule_id="TOOL-004",
                title="Service-identity tool '%s' without restrictions" % tool.name,
                severity="high",
                layer="tool",
                description=(
                    "Tool '%s' runs with execution_identity: service but is not "
                    "covered by denied_actions or escalation_rules. Service-identity "
                    "tools have elevated privileges and should be restricted."
                    % tool.name
                ),
                evidence=[
                    "tools[%d].execution_identity = 'service'" % i,
                    "Not found in denied_actions or escalation_rules",
                ],
                spec_path="tools[%d]" % i,
                recommendation=(
                    "Add '%s' to denied_actions or create an escalation rule. "
                    "Prefer short-lived, task-scoped credentials over long-lived "
                    "shared service identities wherever possible." % tool.name
                ),
            )
        )

    return findings


@rule(
    id="TOOL-005",
    name="Confidential data accessed without data boundary",
    layer="tool",
    severity="high",
    types=["rag", "agent", "mcp-agent"],
    description="A data source with sensitivity: confidential exists but data_boundaries do not reference it.",
)
def check_confidential_data_boundary(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    confidential_sources = []
    for i, ds in enumerate(spec.data_sources or []):
        if getattr(ds, "sensitivity", None) == "confidential":
            confidential_sources.append((i, ds))

    if not confidential_sources:
        return findings

    # Check if data_boundaries reference the confidential sources
    boundaries_text = ""
    if spec.policies and spec.policies.data_boundaries:
        boundaries_text = " ".join(spec.policies.data_boundaries).lower()

    for i, ds in confidential_sources:
        ds_lower = ds.name.lower()
        if ds_lower in boundaries_text or "confidential" in boundaries_text:
            continue

        findings.append(
            Finding(
                id="",
                rule_id="TOOL-005",
                title="Confidential data source '%s' without data boundary" % ds.name,
                severity="high",
                layer="tool",
                description=(
                    "Data source '%s' is classified as sensitivity: confidential "
                    "but is not referenced in policies.data_boundaries. Confidential "
                    "data requires explicit handling rules." % ds.name
                ),
                evidence=[
                    "data_sources[%d].sensitivity = 'confidential'" % i,
                    "policies.data_boundaries does not reference '%s'" % ds.name,
                ],
                spec_path="data_sources[%d]" % i,
                recommendation=(
                    "Add a data boundary for confidential source '%s'. Example: "
                    "'Data from %s is confidential — never include in responses "
                    "without explicit user authorization.'" % (ds.name, ds.name)
                ),
            )
        )

    return findings


# Patterns for detecting egress-capable tools by name
_EGRESS_NAME_PATTERNS = [
    r"send",
    r"email",
    r"webhook",
    r"upload",
    r"post(?:_|$)",
    r"deliver",
    r"notify",
    r"forward",
    r"publish",
    r"broadcast",
    r"dispatch",
    r"transmit",
]

# Patterns for detecting egress-capable tools by description
_EGRESS_DESC_PATTERNS = [
    r"send\s+to",
    r"upload\s+to",
    r"webhook",
    r"outbound",
    r"external\s+(?:api|endpoint|service)",
    r"deliver\s+(?:to|via)",
    r"post\s+(?:to|data)",
    r"notify\s+(?:via|through)",
]


def _is_egress_capable_tool(tool):
    # type: (ToolDef) -> bool
    """Check if a tool can transmit data outside the trust boundary."""
    if getattr(tool, "effect", None) == "external_send":
        return True

    lower_name = tool.name.lower()
    for pattern in _EGRESS_NAME_PATTERNS:
        if re.search(pattern, lower_name):
            return True

    lower_desc = tool.description.lower()
    for pattern in _EGRESS_DESC_PATTERNS:
        if re.search(pattern, lower_desc):
            return True

    return False


@rule(
    id="TOOL-006",
    name="Confidential data with egress-capable tool",
    layer="tool",
    severity="critical",
    types=["agent", "mcp-agent"],
    description="Agent has confidential data sources and egress-capable tools, risking data exfiltration.",
)
def check_confidential_data_external_send(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    has_confidential = any(
        getattr(ds, "sensitivity", None) == "confidential"
        for ds in (spec.data_sources or [])
    )
    if not has_confidential:
        return findings

    egress_tools = [
        (i, t) for i, t in enumerate(spec.tools or []) if _is_egress_capable_tool(t)
    ]
    if not egress_tools:
        return findings

    confidential_names = [
        ds.name
        for ds in (spec.data_sources or [])
        if getattr(ds, "sensitivity", None) == "confidential"
    ]
    for i, tool in egress_tools:
        findings.append(
            Finding(
                id="",
                rule_id="TOOL-006",
                title=("Confidential data exfiltration risk via '%s'" % tool.name),
                severity="critical",
                layer="tool",
                description=(
                    "Tool '%s' is egress-capable and the agent accesses "
                    "confidential data sources (%s). A prompt injection could "
                    "exfiltrate confidential data through this tool."
                    % (tool.name, ", ".join(confidential_names))
                ),
                evidence=[
                    "tools[%d] ('%s') is egress-capable" % (i, tool.name),
                    "Confidential data sources: %s" % ", ".join(confidential_names),
                ],
                spec_path="tools[%d]" % i,
                recommendation=(
                    "Add strict controls around '%s' when confidential data is "
                    "present. Use escalation rules, destination allowlists, "
                    "content filtering/DLP, and per-action review, or remove "
                    "the egress capability." % tool.name
                ),
            )
        )

    return findings


# ---- TOOL-007 helpers ----

# Tool names/effects that indicate dangerous capability
_DANGEROUS_TOOL_PATTERNS = [
    r"exec(?:ute)?",
    r"run",
    r"shell",
    r"command",
    r"sql",
    r"query",
    r"eval",
    r"script",
    r"write_file",
    r"delete_file",
    r"http",
    r"curl",
    r"fetch",
    r"request",
]

# Parameter names that are dangerous when unconstrained
_DANGEROUS_PARAM_NAMES = {
    "command",
    "cmd",
    "sql",
    "query",
    "code",
    "script",
    "path",
    "file_path",
    "filepath",
    "url",
    "uri",
    "endpoint",
    "body",
    "payload",
    "recipient",
    "to",
    "headers",
    "shell",
    "expression",
    "exec",
    "input",
}


def _is_dangerous_tool(tool):
    # type: (ToolDef) -> bool
    """Check if tool indicates command/query execution, filesystem, or network access."""
    if getattr(tool, "effect", None) in ("write", "delete", "external_send"):
        return True
    lower = tool.name.lower()
    for pattern in _DANGEROUS_TOOL_PATTERNS:
        if re.search(pattern, lower):
            return True
    lower_desc = tool.description.lower()
    for kw in (
        "execute",
        "run command",
        "run shell",
        "sql",
        "query",
        "file system",
        "filesystem",
        "http request",
        "network",
    ):
        if kw in lower_desc:
            return True
    return False


def _param_is_constrained(param_schema):
    # type: (Dict) -> bool
    """Check if a parameter schema has meaningful constraints."""
    if not isinstance(param_schema, dict):
        return False
    for key in ("enum", "const", "pattern", "format", "maxLength"):
        if key in param_schema:
            return True
    if param_schema.get("additionalProperties") is False:
        return True
    if param_schema.get("type") not in (None, "string", "object"):
        # Non-string, non-object types (integer, boolean, array) are more constrained
        return True
    return False


@rule(
    id="TOOL-007",
    name="Dangerous tool with unconstrained free-form parameters",
    layer="tool",
    severity="high",
    types=["agent", "mcp-agent"],
    description="A dangerous tool exposes free-form parameters without schema constraints.",
)
def check_unconstrained_dangerous_params(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    if not spec.tools:
        return findings

    for i, tool in enumerate(spec.tools):
        if not _is_dangerous_tool(tool):
            continue

        params = tool.parameters
        if not params or not isinstance(params, dict):
            continue

        properties = params.get("properties", {})
        if not isinstance(properties, dict):
            continue

        unconstrained = []
        for pname, pschema in properties.items():
            if pname.lower() in _DANGEROUS_PARAM_NAMES:
                if not _param_is_constrained(pschema):
                    unconstrained.append(pname)

        if not unconstrained:
            continue

        findings.append(
            Finding(
                id="",
                rule_id="TOOL-007",
                title="Dangerous tool '%s' with unconstrained parameters: %s"
                % (tool.name, ", ".join(unconstrained)),
                severity="high",
                layer="tool",
                description=(
                    "Tool '%s' can perform dangerous operations and exposes "
                    "unconstrained free-form parameters (%s). An attacker could "
                    "craft arbitrary inputs via prompt injection."
                    % (tool.name, ", ".join(unconstrained))
                ),
                evidence=[
                    "tools[%d].name = '%s' is a dangerous tool" % (i, tool.name),
                    "Unconstrained parameters: %s" % ", ".join(unconstrained),
                ],
                spec_path="tools[%d]" % i,
                recommendation=(
                    "Replace open-ended parameters with task-specific structured "
                    "parameters and enforce fail-closed schema validation before "
                    "tool invocation."
                ),
            )
        )

    return findings


# ---- TOOL-008 helpers ----

_OVERLY_GENERIC_NAMES = {
    "run",
    "do",
    "get",
    "set",
    "call",
    "exec",
    "action",
    "tool",
    "execute",
    "invoke",
    "process",
    "handle",
    "perform",
}


@rule(
    id="TOOL-008",
    name="Ambiguous tool names or namespace collision",
    layer="tool",
    severity="medium",
    types=["agent", "mcp-agent"],
    description="Duplicate, confusingly similar, or overly generic tool names detected.",
)
def check_ambiguous_tool_names(spec):
    # type: (AgentSpec) -> List[Finding]
    findings = []

    if not spec.tools:
        return findings

    # Collect all tool names from tools + mcp_servers.allowed_tools
    all_names = []
    for t in spec.tools:
        all_names.append(t.name)
    for ms in spec.mcp_servers or []:
        for tool_name in ms.allowed_tools or []:
            all_names.append(tool_name)

    # Check for duplicates
    seen = {}
    for name in all_names:
        lower = name.lower()
        if lower in seen:
            findings.append(
                Finding(
                    id="",
                    rule_id="TOOL-008",
                    title="Duplicate tool name: '%s'" % name,
                    severity="medium",
                    layer="tool",
                    description=(
                        "Tool name '%s' appears multiple times across tools and/or "
                        "MCP server allowed_tools. This can cause mis-resolution."
                        % name
                    ),
                    evidence=[
                        "Tool name '%s' is duplicated" % name,
                    ],
                    spec_path="tools",
                    recommendation=(
                        "Use fully qualified tool names, explicit namespaces, "
                        "version pinning, and fail-closed disambiguation when "
                        "tool resolution is ambiguous."
                    ),
                )
            )
            break  # One finding for duplicates is enough
        seen[lower] = name

    # Check for overly generic names
    for idx, tool in enumerate(spec.tools):
        if tool.name.lower() in _OVERLY_GENERIC_NAMES:
            findings.append(
                Finding(
                    id="",
                    rule_id="TOOL-008",
                    title="Overly generic tool name: '%s'" % tool.name,
                    severity="medium",
                    layer="tool",
                    description=(
                        "Tool '%s' has an overly generic name that can be confusing "
                        "or mis-resolved, especially when multiple tools are available."
                        % tool.name
                    ),
                    evidence=[
                        "tools[%d].name = '%s' is overly generic" % (idx, tool.name),
                    ],
                    spec_path="tools[%d]" % idx,
                    recommendation=(
                        "Use descriptive, fully qualified tool names. Avoid "
                        "generic names like 'run', 'get', 'call', 'exec'."
                    ),
                )
            )

    return findings
