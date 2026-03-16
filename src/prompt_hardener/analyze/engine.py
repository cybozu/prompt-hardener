"""Orchestrator: spec -> rules -> findings -> scoring -> report."""

import hashlib
from datetime import datetime, timezone

from prompt_hardener.agent_spec import load_and_validate
from prompt_hardener.analyze.attack_paths import enumerate_attack_paths
from prompt_hardener.analyze.report import (
    AnalyzeMetadata,
    AnalyzeReport,
    AnalyzeSummary,
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
):
    # type: (Union[str, AgentSpec], Optional[List[str]]) -> AnalyzeReport
    """Run deterministic static analysis on an agent spec file.

    Args:
        spec_path_or_spec: Path to the agent_spec.yaml file, or an AgentSpec object.
        layers: Optional list of layers to analyze (e.g., ["prompt", "tool"]).

    Returns:
        AnalyzeReport with findings, scores, attack paths, and fixes.

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
    scores_by_layer, overall_score, risk_level = compute_scores(
        all_findings, spec.type, layers=layers
    )

    # Derive attack paths and fixes
    attack_paths = enumerate_attack_paths(spec, all_findings)
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

    return AnalyzeReport(
        metadata=metadata,
        summary=summary,
        findings=all_findings,
        attack_paths=attack_paths,
        recommended_fixes=fixes,
    )
