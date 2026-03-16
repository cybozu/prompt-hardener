"""Template instantiation for attack paths."""

from prompt_hardener.analyze.attack_paths.models import PathDraft, PathNode


RELATED_RULES = {
    "unauthorized_tool_execution": [
        "PROMPT-003",
        "TOOL-001",
        "TOOL-003",
        "TOOL-004",
        "TOOL-007",
        "ARCH-002",
        "ARCH-007",
    ],
    "retrieved_content_tool_misuse": [
        "PROMPT-001",
        "TOOL-001",
        "TOOL-003",
        "TOOL-004",
        "TOOL-005",
        "ARCH-003",
    ],
    "tool_output_secondary_tool_misuse": [
        "ARCH-002",
        "TOOL-001",
        "TOOL-003",
        "TOOL-004",
        "TOOL-007",
    ],
    "confidential_data_exfiltration": [
        "TOOL-005",
        "TOOL-006",
        "TOOL-003",
        "TOOL-004",
        "PROMPT-003",
    ],
    "cross_tenant_access": [
        "ARCH-005",
        "ARCH-006",
        "TOOL-003",
        "TOOL-004",
    ],
    "persistent_memory_poisoning": [
        "ARCH-004",
        "TOOL-001",
        "TOOL-003",
        "TOOL-004",
    ],
    "mcp_trust_abuse": [
        "ARCH-001",
        "ARCH-003",
        "TOOL-003",
        "TOOL-004",
    ],
    "system_prompt_leakage": [
        "PROMPT-002",
        "PROMPT-003",
    ],
}


def _related_finding_ids(findings_by_rule, category):
    ids = []
    for rule_id in RELATED_RULES.get(category, []):
        ids.extend(findings_by_rule.get(rule_id, []))
    return sorted(set(ids))


def _impact_for_tool(tool):
    if tool.effect == "delete":
        return ["destructive action"]
    if tool.can_modify_state:
        return ["unauthorized write"]
    if tool.can_egress:
        return ["unauthorized write"]
    return ["unauthorized write"]


def _target_for_tool(tool):
    if tool.can_egress:
        return PathNode(type="asset", name="external_channel")
    return PathNode(type="asset", name="backend_state")


def _blockers(surface, tool=None):
    blockers = []
    if surface.controls.has_budget_limits:
        blockers.append("Execution budget/rate limits cap autonomous tool chaining")
    if tool and surface.controls.is_denied(tool.name):
        blockers.append("Tool is explicitly denied in policies.denied_actions")
    return blockers


def _missing_controls(*controls):
    return [control for control in controls if control]


def instantiate_templates(surface, findings_by_rule):
    # type: (NormalizedSpec, Dict[str, List[str]]) -> List[PathDraft]
    paths = []

    # 1. User prompt injection -> sensitive tool misuse
    for tool in surface.tools:
        if not (tool.is_sensitive or tool.is_high_impact or tool.has_service_identity):
            continue
        missing_controls = []
        if not surface.controls.has_user_input_distrust:
            missing_controls.append("missing distrust instruction")
        if not surface.controls.has_escalation_for(tool.name):
            missing_controls.append("missing escalation")
        if not surface.controls.has_budget_limits:
            missing_controls.append("missing budget/limit")
        if not missing_controls:
            continue
        exposures = []
        if tool.has_service_identity:
            exposures.append("service identity")
        if tool.can_egress:
            exposures.append("external egress")
        paths.append(
            PathDraft(
                category="unauthorized_tool_execution",
                title="Prompt injection triggers unauthorized tool execution via %s"
                % tool.name,
                entrypoint=PathNode(type="entrypoint", name="user_message"),
                chain=[
                    PathNode(type="control", name="llm"),
                    PathNode(type="capability", name=tool.name),
                ],
                target=_target_for_tool(tool),
                impact=_impact_for_tool(tool),
                description=(
                    "A crafted user message can steer the model into invoking '%s' "
                    "without the intended approval or distrust checks."
                    % tool.name
                ),
                preconditions=[
                    "The attacker can send a user message to the agent",
                ],
                blockers=_blockers(surface, tool),
                evidence=[
                    "Tool '%s' is marked sensitive or high impact" % tool.name,
                ],
                recommended_mitigations=[
                    "Add an explicit user-input distrust instruction",
                    "Add escalation coverage for '%s'" % tool.name,
                    "Set execution budgets or rate limits",
                ],
                related_findings=_related_finding_ids(
                    findings_by_rule, "unauthorized_tool_execution"
                ),
                inferred_hops=0,
                boundary_crossings=1,
                metadata={
                    "exposures": "|".join(exposures),
                    "missing_controls": "|".join(missing_controls),
                },
            )
        )

    # 2. Untrusted retrieved content -> tool misuse
    untrusted_sources = [ds for ds in surface.data_sources if ds.is_untrusted]
    dangerous_tools = [
        tool
        for tool in surface.tools
        if tool.is_sensitive or tool.is_high_impact or tool.has_service_identity
    ]
    if untrusted_sources:
        for data_source in untrusted_sources:
            candidate_tools = dangerous_tools or [None]
            for tool in candidate_tools:
                missing_controls = []
                if not surface.controls.has_retrieved_content_distrust:
                    missing_controls.append("missing distrust instruction")
                if tool and not surface.controls.has_escalation_for(tool.name):
                    missing_controls.append("missing escalation")
                if not missing_controls:
                    continue
                exposures = []
                if tool and tool.has_service_identity:
                    exposures.append("service identity")
                if tool and tool.can_egress:
                    exposures.append("external egress")
                chain = [
                    PathNode(type="asset", name=data_source.name),
                    PathNode(type="control", name="llm"),
                ]
                target = PathNode(type="asset", name="response_channel")
                impact = ["prompt leak"]
                title = "Untrusted retrieved content can steer model output via %s" % (
                    data_source.name,
                )
                description = (
                    "Untrusted retrieved content from '%s' can be treated as "
                    "instructions and shape the model response."
                    % data_source.name
                )
                evidence = [
                    "Data source '%s' is untrusted or unknown" % data_source.name,
                ]
                mitigations = [
                    "Mark retrieved content as untrusted data in prompt/policies",
                ]
                blockers = _blockers(surface)
                if tool:
                    chain.append(PathNode(type="capability", name=tool.name))
                    target = _target_for_tool(tool)
                    impact = _impact_for_tool(tool)
                    title = "Untrusted retrieved content can steer %s via %s" % (
                        tool.name,
                        data_source.name,
                    )
                    description = (
                        "Untrusted retrieved content from '%s' can be treated as "
                        "instructions and propagated into '%s'."
                        % (data_source.name, tool.name)
                    )
                    evidence.append(
                        "Tool '%s' can change state or act with privilege"
                        % tool.name
                    )
                    mitigations.append(
                        "Add escalation coverage for '%s'" % tool.name
                    )
                    blockers = _blockers(surface, tool)
                paths.append(
                    PathDraft(
                        category="retrieved_content_tool_misuse",
                        title=title,
                        entrypoint=PathNode(type="entrypoint", name="retrieved_content"),
                        chain=chain,
                        target=target,
                        impact=impact,
                        description=description,
                        preconditions=[
                            "The agent retrieves content from '%s'" % data_source.name,
                        ],
                        blockers=blockers,
                        evidence=evidence,
                        recommended_mitigations=mitigations,
                        related_findings=_related_finding_ids(
                            findings_by_rule, "retrieved_content_tool_misuse"
                        ),
                        inferred_hops=0 if tool else 1,
                        boundary_crossings=2 if tool else 1,
                        metadata={
                            "exposures": "|".join(exposures),
                            "missing_controls": "|".join(missing_controls),
                        },
                    )
                )

    # 3. Tool output injection -> secondary tool misuse
    if len(surface.tools) >= 2 and not surface.controls.has_tool_output_distrust:
        for tool in dangerous_tools:
            missing_controls = ["missing distrust instruction"]
            if not surface.controls.has_escalation_for(tool.name):
                missing_controls.append("missing escalation")
            paths.append(
                PathDraft(
                    category="tool_output_secondary_tool_misuse",
                    title="Tool output injection can trigger secondary action via %s"
                    % tool.name,
                    entrypoint=PathNode(type="entrypoint", name="tool_result"),
                    chain=[
                        PathNode(type="control", name="llm"),
                        PathNode(type="capability", name=tool.name),
                    ],
                    target=_target_for_tool(tool),
                    impact=_impact_for_tool(tool),
                    description=(
                        "A malicious tool result can be reinterpreted as instructions, "
                        "leading the model to call '%s'."
                        % tool.name
                    ),
                    preconditions=[
                        "At least one tool returns content that the model consumes",
                    ],
                    blockers=_blockers(surface, tool),
                    evidence=[
                        "No tool-result distrust or validation guidance is present",
                    ],
                    recommended_mitigations=[
                        "Treat tool output as untrusted and verify before reuse",
                        "Add escalation coverage for '%s'" % tool.name,
                    ],
                    related_findings=_related_finding_ids(
                        findings_by_rule, "tool_output_secondary_tool_misuse"
                    ),
                    inferred_hops=0,
                    boundary_crossings=1,
                    metadata={
                        "exposures": "|".join(
                            value
                            for value in (
                                "service identity" if tool.has_service_identity else "",
                                "external egress" if tool.can_egress else "",
                            )
                            if value
                        ),
                        "missing_controls": "|".join(missing_controls),
                    },
                )
            )

    # 4. Confidential data read -> external send exfiltration
    confidential_sources = [ds for ds in surface.data_sources if ds.is_confidential]
    egress_tools = [tool for tool in surface.tools if tool.can_egress]
    if confidential_sources and egress_tools:
        for data_source in confidential_sources:
            for tool in egress_tools:
                missing_controls = ["missing data boundary"]
                if not surface.controls.has_escalation_for(tool.name):
                    missing_controls.append("missing escalation")
                paths.append(
                    PathDraft(
                        category="confidential_data_exfiltration",
                        title="Confidential data from %s can be exfiltrated via %s"
                        % (data_source.name, tool.name),
                        entrypoint=PathNode(type="entrypoint", name="user_message"),
                        chain=[
                            PathNode(type="control", name="llm"),
                            PathNode(type="asset", name=data_source.name),
                            PathNode(type="capability", name=tool.name),
                        ],
                        target=PathNode(type="asset", name="external_channel"),
                        impact=["confidential data exfiltration"],
                        description=(
                            "The agent can read confidential data from '%s' and send "
                            "it outside the boundary through '%s'."
                            % (data_source.name, tool.name)
                        ),
                        preconditions=[
                            "The model can access '%s'" % data_source.name,
                        ],
                        blockers=_blockers(surface, tool),
                        evidence=[
                            "Data source '%s' is confidential" % data_source.name,
                            "Tool '%s' can send data externally" % tool.name,
                        ],
                        recommended_mitigations=[
                            "Add explicit data boundaries for confidential sources",
                            "Require approval and destination allowlists for '%s'"
                            % tool.name,
                        ],
                        related_findings=_related_finding_ids(
                            findings_by_rule, "confidential_data_exfiltration"
                        ),
                        inferred_hops=1,
                        boundary_crossings=2,
                        metadata={
                            "exposures": "confidential data|external egress",
                            "missing_controls": "|".join(missing_controls),
                        },
                    )
                )

    # 5. Multi-tenant cross-tenant access
    if surface.scope == "multi_tenant" and not surface.controls.has_tenant_isolation:
        for tool in dangerous_tools or surface.tools:
            if not (tool.can_modify_state or tool.can_read_data or tool.has_service_identity):
                continue
            missing_controls = ["missing tenant isolation"]
            if not surface.controls.has_escalation_for(tool.name):
                missing_controls.append("missing escalation")
            impact = ["cross-tenant exposure"]
            if tool.can_modify_state:
                impact.append("unauthorized write")
            paths.append(
                PathDraft(
                    category="cross_tenant_access",
                    title="Cross-tenant access is possible through %s" % tool.name,
                    entrypoint=PathNode(type="entrypoint", name="user_message"),
                    chain=[
                        PathNode(type="control", name="llm"),
                        PathNode(type="capability", name=tool.name),
                    ],
                    target=PathNode(type="asset", name="cross_tenant_data"),
                    impact=impact,
                    description=(
                        "In multi-tenant scope, '%s' can operate across tenant "
                        "boundaries without explicit isolation controls."
                        % tool.name
                    ),
                    preconditions=[
                        "The agent serves more than one tenant",
                    ],
                    blockers=_blockers(surface, tool),
                    evidence=[
                        "Agent scope is multi_tenant",
                    ],
                    recommended_mitigations=[
                        "Enforce per-tenant isolation for retrieval, memory, and tools",
                        "Require approval for cross-tenant or service-identity actions",
                    ],
                    related_findings=_related_finding_ids(
                        findings_by_rule, "cross_tenant_access"
                    ),
                    inferred_hops=1,
                    boundary_crossings=2,
                    metadata={
                        "exposures": "multi-tenant|service identity"
                        if tool.has_service_identity
                        else "multi-tenant",
                        "missing_controls": "|".join(missing_controls),
                    },
                )
            )

    # 6. Persistent memory poisoning
    if surface.has_persistent_memory and not surface.controls.has_memory_protection:
        sink_tool = None
        for tool in dangerous_tools:
            sink_tool = tool
            break
        chain = [PathNode(type="control", name="llm")]
        if sink_tool:
            chain.append(PathNode(type="capability", name=sink_tool.name))
        paths.append(
            PathDraft(
                category="persistent_memory_poisoning",
                title="Poisoned persistent memory can survive into future sessions",
                entrypoint=PathNode(type="entrypoint", name="persistent_memory"),
                chain=chain,
                target=PathNode(type="asset", name="memory_store"),
                impact=["persistent poisoning"],
                description=(
                    "Persisted attacker-influenced state can be re-consumed by the "
                    "model and shape later actions."
                ),
                preconditions=[
                    "The agent stores memory across sessions",
                ],
                blockers=_blockers(surface, sink_tool),
                evidence=[
                    "Persistent memory is enabled",
                    "No memory protection signals were found",
                ],
                recommended_mitigations=[
                    "Validate, scope, and expire memory before reuse",
                    "Do not automatically re-ingest model-generated memory into trust",
                ],
                related_findings=_related_finding_ids(
                    findings_by_rule, "persistent_memory_poisoning"
                ),
                inferred_hops=1 if sink_tool else 0,
                boundary_crossings=1,
                metadata={
                    "exposures": "service identity" if sink_tool and sink_tool.has_service_identity else "",
                    "missing_controls": "missing distrust instruction",
                },
            )
        )

    # 7. MCP third-party trust abuse
    for server in surface.mcp_servers:
        if not server.is_untrusted:
            continue
        if server.has_tool_restrictions:
            continue
        exposed_tools = dangerous_tools or surface.tools
        if not exposed_tools:
            continue
        for tool in exposed_tools:
            missing_controls = ["missing MCP tool restriction"]
            if not surface.controls.has_escalation_for(tool.name):
                missing_controls.append("missing escalation")
            paths.append(
                PathDraft(
                    category="mcp_trust_abuse",
                    title="Untrusted MCP server %s can reach %s"
                    % (server.name, tool.name),
                    entrypoint=PathNode(type="entrypoint", name="mcp_response"),
                    chain=[
                        PathNode(type="capability", name=server.name),
                        PathNode(type="control", name="llm"),
                        PathNode(type="capability", name=tool.name),
                    ],
                    target=_target_for_tool(tool),
                    impact=_impact_for_tool(tool),
                    description=(
                        "An untrusted MCP server without tool restrictions can "
                        "influence the model and reach '%s'."
                        % tool.name
                    ),
                    preconditions=[
                        "The MCP server can return attacker-influenced content",
                    ],
                    blockers=_blockers(surface, tool),
                    evidence=[
                        "MCP server '%s' is untrusted" % server.name,
                        "No allowed_tools restriction is configured",
                    ],
                    recommended_mitigations=[
                        "Constrain untrusted MCP servers with allowed_tools",
                        "Treat MCP output as untrusted and gate high-impact tools",
                    ],
                    related_findings=_related_finding_ids(
                        findings_by_rule, "mcp_trust_abuse"
                    ),
                    inferred_hops=0,
                    boundary_crossings=2,
                    metadata={
                        "exposures": "|".join(
                            value
                            for value in (
                                "service identity" if tool.has_service_identity else "",
                                "external egress" if tool.can_egress else "",
                            )
                            if value
                        ),
                        "missing_controls": "|".join(missing_controls),
                    },
                )
            )

    # 8. System prompt leakage
    if findings_by_rule.get("PROMPT-002") and not surface.controls.has_user_input_distrust:
        paths.append(
            PathDraft(
                category="system_prompt_leakage",
                title="Prompt injection can disclose hidden system instructions",
                entrypoint=PathNode(type="entrypoint", name="user_message"),
                chain=[PathNode(type="control", name="llm")],
                target=PathNode(type="asset", name="system_prompt"),
                impact=["prompt leak"],
                description=(
                    "Because user input is not explicitly treated as untrusted, a "
                    "prompt injection can pressure the model to reveal hidden prompt content."
                ),
                preconditions=[
                    "The system prompt contains hidden instructions or sensitive content",
                ],
                blockers=_blockers(surface),
                evidence=[
                    "Sensitive prompt material was detected",
                ],
                recommended_mitigations=[
                    "Remove secrets from the system prompt",
                    "Add explicit instructions never to reveal hidden prompts",
                ],
                related_findings=_related_finding_ids(
                    findings_by_rule, "system_prompt_leakage"
                ),
                inferred_hops=0,
                boundary_crossings=1,
                metadata={
                    "exposures": "",
                    "missing_controls": "missing distrust instruction",
                },
            )
        )

    return paths
