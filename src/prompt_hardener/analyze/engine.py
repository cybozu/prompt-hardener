"""Orchestrator: spec -> rules -> findings -> scoring -> report."""

import hashlib
from datetime import datetime, timezone

from prompt_hardener.agent_spec import load_and_validate
from prompt_hardener.analyze.report import (
    AnalyzeMetadata,
    AnalyzeReport,
    AnalyzeSummary,
    AttackPath,
    RecommendedFix,
)
from prompt_hardener.analyze.rules import _ensure_rules_loaded, get_rules
from prompt_hardener.analyze.scoring import compute_scores
from prompt_hardener.models import AgentSpec

TOOL_VERSION = "0.5.0"
RULES_VERSION = "1.0"


def _compute_spec_digest(spec_path):
    # type: (str) -> str
    with open(spec_path, "rb") as f:
        return "sha256:" + hashlib.sha256(f.read()).hexdigest()[:16]


def _assign_finding_ids(findings):
    # type: (List[Finding]) -> None
    for i, f in enumerate(findings):
        f.id = "finding-%03d" % (i + 1)


def _derive_attack_paths(findings, spec):
    # type: (List[Finding], AgentSpec) -> List[AttackPath]
    """Generate attack path templates from findings."""
    paths = []
    counter = 0

    # Group findings by rule for combined attack paths
    untrusted_data_findings = [f for f in findings if f.rule_id == "PROMPT-001"]
    tool_findings = [
        f for f in findings
        if f.rule_id in ("TOOL-001", "TOOL-003", "TOOL-004", "ARCH-001")
    ]
    mcp_findings = [f for f in findings if f.rule_id == "ARCH-002"]
    unknown_trust_findings = [f for f in findings if f.rule_id == "ARCH-004"]
    memory_findings = [f for f in findings if f.rule_id == "ARCH-005"]
    scope_findings = [f for f in findings if f.rule_id == "ARCH-006"]
    confidential_exfil_findings = [f for f in findings if f.rule_id == "TOOL-006"]

    if untrusted_data_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="Indirect prompt injection via untrusted data source",
                severity="high",
                description=(
                    "An attacker can inject malicious instructions through an untrusted "
                    "data source. Without instruction/data boundaries, injected content "
                    "may be interpreted as system instructions."
                ),
                steps=[
                    "Attacker crafts content containing injected instructions",
                    "Content is ingested through an untrusted data source",
                    "RAG retrieval or data processing includes the malicious content",
                    "Without boundary markers, injected content is treated as instructions",
                    "Agent follows attacker-controlled instructions",
                ],
                related_findings=[f.id for f in untrusted_data_findings],
            )
        )

    if tool_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="Unauthorized tool execution via prompt injection",
                severity="high",
                description=(
                    "Without proper escalation rules or human-in-the-loop controls, "
                    "a prompt injection attack could trigger sensitive tool calls "
                    "without user approval."
                ),
                steps=[
                    "Attacker injects instructions via user message or tool result",
                    "Injected instructions request execution of sensitive tools",
                    "Agent executes the tool without requiring human approval",
                    "Sensitive operation is performed without authorization",
                ],
                related_findings=[f.id for f in tool_findings],
            )
        )

    if mcp_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="MCP server compromise leading to broad tool access",
                severity="high",
                description=(
                    "An untrusted MCP server without tool restrictions could be "
                    "compromised and used to invoke any available tool."
                ),
                steps=[
                    "Untrusted MCP server is compromised or returns malicious responses",
                    "Without allowed_tools restrictions, server can invoke any tool",
                    "Attacker gains access to sensitive operations through the MCP server",
                ],
                related_findings=[f.id for f in mcp_findings],
            )
        )

    if unknown_trust_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="Unassessed trust level leading to unexpected exposure",
                severity="medium",
                description=(
                    "Data sources or MCP servers with unknown trust levels have "
                    "not been properly assessed, creating blind spots in the "
                    "security posture."
                ),
                steps=[
                    "Data source or MCP server with unknown trust level is deployed",
                    "Attacker compromises the unassessed source",
                    "Without proper trust classification, no defensive measures are in place",
                ],
                related_findings=[f.id for f in unknown_trust_findings],
            )
        )

    # Check for external_send tools (from spec, not just findings)
    has_external_send = False
    if spec.tools:
        has_external_send = any(
            getattr(t, "effect", None) == "external_send" for t in spec.tools
        )
    if has_external_send and tool_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="Sensitive data exfiltration via external_send tool",
                severity="high",
                description=(
                    "An external_send tool could be exploited via prompt injection "
                    "to exfiltrate sensitive data to an attacker-controlled endpoint."
                ),
                steps=[
                    "Attacker crafts prompt injection to trigger external_send tool",
                    "Injected instructions include attacker-controlled destination",
                    "Sensitive data is sent to the attacker's endpoint",
                ],
                related_findings=[f.id for f in tool_findings],
            )
        )

    if memory_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="Memory poisoning leading to persistent compromise",
                severity="high",
                description=(
                    "An agent with persistent memory and no poisoning protection "
                    "can be compromised by injecting malicious state that persists "
                    "across sessions."
                ),
                steps=[
                    "Attacker crafts a message that instructs the agent to store malicious state",
                    "Agent stores the injected data in persistent memory",
                    "In subsequent sessions, the agent uses the poisoned state",
                    "Attacker gains persistent control over agent behavior",
                ],
                related_findings=[f.id for f in memory_findings],
            )
        )

    if scope_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="Cross-tenant data exposure",
                severity="high",
                description=(
                    "A multi-tenant agent with sensitive tools may allow "
                    "cross-tenant data access through prompt injection."
                ),
                steps=[
                    "Attacker operates within one tenant of the multi-tenant system",
                    "Prompt injection triggers sensitive tool with cross-tenant scope",
                    "Data from other tenants is exposed to the attacker",
                ],
                related_findings=[f.id for f in scope_findings],
            )
        )

    if confidential_exfil_findings:
        counter += 1
        paths.append(
            AttackPath(
                id="path-%03d" % counter,
                name="Confidential data exfiltration",
                severity="critical",
                description=(
                    "The combination of confidential data sources and external_send "
                    "tools creates a direct path for data exfiltration via prompt "
                    "injection."
                ),
                steps=[
                    "Attacker crafts prompt injection targeting the external_send tool",
                    "Injected instructions reference confidential data sources",
                    "Tool sends confidential data to attacker-controlled destination",
                ],
                related_findings=[f.id for f in confidential_exfil_findings],
            )
        )

    return paths


def _derive_fixes(findings):
    # type: (List[Finding]) -> List[RecommendedFix]
    """Generate recommended fixes from findings."""
    fixes = []
    for i, f in enumerate(findings):
        # Map severity to effort (heuristic: prompt fixes are low effort)
        effort = "low" if f.layer == "prompt" else "medium"
        fixes.append(
            RecommendedFix(
                id="fix-%03d" % (i + 1),
                finding_id=f.id,
                layer=f.layer,
                title=f.recommendation.split(".")[0]
                if f.recommendation
                else "Fix %s" % f.rule_id,
                description=f.recommendation,
                priority=f.severity,
                effort=effort,
            )
        )
    return fixes


def _compute_finding_counts(findings):
    # type: (List[Finding]) -> Dict[str, int]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
        counts["total"] += 1
    return counts


def run_analyze(
    spec_path_or_spec,
    layers=None,
    eval_api_mode=None,
    eval_model=None,
    apply_techniques=None,
    aws_region=None,
    aws_profile=None,
):
    # type: (Union[str, AgentSpec], Optional[List[str]], Optional[str], Optional[str], Optional[List[str]], Optional[str], Optional[str]) -> AnalyzeReport
    """Run static analysis on an agent spec file, with optional LLM evaluation.

    Args:
        spec_path_or_spec: Path to the agent_spec.yaml file, or an AgentSpec object.
        layers: Optional list of layers to analyze (e.g., ["prompt", "tool"]).
        eval_api_mode: LLM API for prompt-layer evaluation (optional).
            If not specified, only static analysis is performed.
        eval_model: Model for prompt-layer evaluation (optional).
        apply_techniques: Techniques for prompt evaluation (optional).
        aws_region: AWS region for Bedrock (optional).
        aws_profile: AWS profile for Bedrock (optional).

    Returns:
        AnalyzeReport with findings, scores, attack paths, fixes,
        and optionally prompt_evaluation/prompt_eval_score.

    Raises:
        ValueError: If the spec file cannot be loaded.
        SystemExit: If the spec has validation errors.
    """
    # Load and validate
    if isinstance(spec_path_or_spec, AgentSpec):
        spec = spec_path_or_spec
        spec_path = None
        spec_digest = "N/A"
    else:
        spec_path = spec_path_or_spec
        spec, result = load_and_validate(spec_path)
        if not result.is_valid:
            error_msgs = "; ".join(str(e) for e in result.errors)
            raise SystemExit("Spec validation failed: %s" % error_msgs)
        spec_digest = _compute_spec_digest(spec_path)

    # Ensure rule modules are loaded
    _ensure_rules_loaded()

    # Get applicable rules
    rules = get_rules(agent_type=spec.type, layers=layers)

    # Evaluate rules
    all_findings = []  # type: List[Finding]
    for rule_fn in rules:
        rule_findings = rule_fn(spec)
        all_findings.extend(rule_findings)

    # Assign finding IDs
    _assign_finding_ids(all_findings)

    # Compute scores
    scores_by_layer, overall_score, risk_level = compute_scores(all_findings, spec.type)

    # Derive attack paths and fixes
    attack_paths = _derive_attack_paths(all_findings, spec)
    fixes = _derive_fixes(all_findings)

    # Build metadata
    metadata = AnalyzeMetadata(
        tool_version=TOOL_VERSION,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        agent_name=spec.name,
        agent_type=spec.type,
        spec_digest=spec_digest,
        rules_version=RULES_VERSION,
        rules_evaluated=len(rules),
    )

    # Build summary
    summary = AnalyzeSummary(
        risk_level=risk_level,
        overall_score=overall_score,
        scores_by_layer=scores_by_layer,
        finding_counts=_compute_finding_counts(all_findings),
    )

    # Optional LLM evaluation
    prompt_evaluation = None
    prompt_eval_score = None
    if eval_api_mode is not None and eval_model is not None:
        from prompt_hardener.evaluate import evaluate_prompt
        from prompt_hardener.utils import average_satisfaction

        prompt_input = spec.to_prompt_input()
        agent_context = spec.to_agent_context()
        prompt_evaluation = evaluate_prompt(
            eval_api_mode,
            eval_model,
            prompt_input,
            spec.user_input_description,
            apply_techniques=apply_techniques,
            findings=all_findings or None,
            agent_context=agent_context,
            aws_region=aws_region,
            aws_profile=aws_profile,
        )
        prompt_eval_score = average_satisfaction(prompt_evaluation)

    return AnalyzeReport(
        metadata=metadata,
        summary=summary,
        findings=all_findings,
        attack_paths=attack_paths,
        recommended_fixes=fixes,
        prompt_evaluation=prompt_evaluation,
        prompt_eval_score=prompt_eval_score,
    )
