"""Render AnalyzeReport as Markdown."""

from collections import Counter


def _path_title(path):
    return getattr(path, "title", None) or getattr(path, "name", "")


def _path_entry_name(path):
    entrypoint = getattr(path, "entrypoint", None) or {}
    if isinstance(entrypoint, dict):
        return entrypoint.get("name", "")
    return ""


def _path_target_name(path):
    target = getattr(path, "target", None) or {}
    if isinstance(target, dict):
        return target.get("name", "")
    return ""


def _path_chain_names(path):
    chain = getattr(path, "chain", None) or []
    if chain and isinstance(chain[0], dict):
        return [node.get("name", "") for node in chain]
    steps = getattr(path, "steps", None) or []
    return [step for step in steps[1:-1]]


def _path_impacts(path):
    impact = getattr(path, "impact", None) or []
    if impact:
        return impact
    severity = getattr(path, "severity", "")
    if severity:
        return [severity]
    return []


def _path_steps(path):
    steps = getattr(path, "steps", None) or []
    if steps:
        return steps
    entry = _path_entry_name(path)
    chain = _path_chain_names(path)
    target = _path_target_name(path)
    return [value for value in [entry] + chain + [target] if value]


def _render_attack_path_summary(lines, attack_paths):
    severity_counts = Counter(path.severity for path in attack_paths)
    entry_counts = Counter(_path_entry_name(path) for path in attack_paths if _path_entry_name(path))
    impact_counts = Counter()
    for path in attack_paths:
        impact_counts.update(_path_impacts(path))

    lines.append("### Attack Path Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append("| Total Paths | %d |" % len(attack_paths))
    for severity in ["critical", "high", "medium", "low"]:
        if severity_counts.get(severity, 0):
            lines.append(
                "| %s Paths | %d |"
                % (severity.capitalize(), severity_counts.get(severity, 0))
            )
    if entry_counts:
        top_entries = ", ".join(
            "%s (%d)" % (name, count) for name, count in entry_counts.most_common(3)
        )
        lines.append("| Top Entrypoints | %s |" % top_entries)
    if impact_counts:
        top_impacts = ", ".join(
            "%s (%d)" % (name, count) for name, count in impact_counts.most_common(3)
        )
        lines.append("| Top Impacts | %s |" % top_impacts)
    lines.append("")


def render_markdown(report):
    # type: (AnalyzeReport) -> str
    """Convert an AnalyzeReport to a Markdown string."""
    lines = []

    lines.append("# Prompt Hardener Analysis Report")
    lines.append("")

    m = report.metadata
    lines.append("**Agent:** %s (type: %s)" % (m.agent_name, m.agent_type))
    lines.append("**Generated:** %s" % m.timestamp)
    lines.append(
        "**Tool Version:** %s | **Rules Version:** %s | **Rules Evaluated:** %d"
        % (m.tool_version, m.rules_version, m.rules_evaluated)
    )
    lines.append("")

    s = report.summary
    risk_badge = {
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }.get(s.risk_level, s.risk_level.upper())

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append("| Risk Level | **%s** |" % risk_badge)
    lines.append("| Overall Score | %.1f / 10.0 |" % s.overall_score)
    for layer, score in sorted(s.scores_by_layer.items()):
        lines.append("| %s Layer | %.1f / 10.0 |" % (layer.capitalize(), score))
    lines.append("")

    fc = s.finding_counts
    lines.append("**Findings:** %d total" % fc.get("total", 0))
    parts = []
    for sev in ["critical", "high", "medium", "low"]:
        count = fc.get(sev, 0)
        if count > 0:
            parts.append("%d %s" % (count, sev))
    if parts:
        lines.append(" (%s)" % ", ".join(parts))
    lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("")
        for finding in report.findings:
            lines.append("### %s: %s" % (finding.rule_id, finding.title))
            lines.append("")
            lines.append("- **Severity:** %s" % finding.severity)
            lines.append("- **Layer:** %s" % finding.layer)
            lines.append("- **Spec Path:** `%s`" % finding.spec_path)
            lines.append("")
            lines.append(finding.description)
            lines.append("")
            if finding.evidence:
                lines.append("**Evidence:**")
                for evidence in finding.evidence:
                    lines.append("- %s" % evidence)
                lines.append("")
            if finding.recommendation:
                lines.append("**Recommendation:** %s" % finding.recommendation)
                lines.append("")

    if report.attack_paths:
        lines.append("## Attack Paths")
        lines.append("")
        _render_attack_path_summary(lines, report.attack_paths)

        lines.append("### Ranked Paths")
        lines.append("")
        lines.append("| Rank | Severity | Score | Title | Entry | Via | Target | Confidence |")
        lines.append("|------|----------|-------|-------|-------|-----|--------|------------|")
        for index, attack_path in enumerate(report.attack_paths, 1):
            via = " -> ".join(_path_chain_names(attack_path)) or "-"
            lines.append(
                "| %d | %s | %d | %s | %s | %s | %s | %s |"
                % (
                    index,
                    attack_path.severity,
                    getattr(attack_path, "score", 0),
                    _path_title(attack_path),
                    _path_entry_name(attack_path) or "-",
                    via,
                    _path_target_name(attack_path) or "-",
                    getattr(attack_path, "confidence", ""),
                )
            )
        lines.append("")

        for attack_path in report.attack_paths:
            lines.append("### %s" % _path_title(attack_path))
            lines.append("")
            lines.append(
                "- **Severity:** %s"
                % getattr(attack_path, "severity", "")
            )
            lines.append("- **Score:** %s" % getattr(attack_path, "score", 0))
            lines.append(
                "- **Confidence:** %s" % getattr(attack_path, "confidence", "")
            )
            category = getattr(attack_path, "category", "")
            if category:
                lines.append("- **Category:** %s" % category)
            lines.append(
                "- **Path:** %s"
                % " -> ".join(_path_steps(attack_path))
            )
            lines.append("")
            lines.append(attack_path.description)
            lines.append("")
            impacts = _path_impacts(attack_path)
            if impacts:
                lines.append("**Impact:** %s" % ", ".join(impacts))
                lines.append("")
            preconditions = getattr(attack_path, "preconditions", []) or []
            if preconditions:
                lines.append("**Preconditions:**")
                for item in preconditions:
                    lines.append("- %s" % item)
                lines.append("")
            evidence_items = getattr(attack_path, "evidence", []) or []
            if evidence_items:
                lines.append("**Evidence:**")
                for item in evidence_items:
                    lines.append("- %s" % item)
                lines.append("")
            blockers = getattr(attack_path, "blockers", []) or []
            if blockers:
                lines.append("**Blockers / Existing Controls:**")
                for item in blockers:
                    lines.append("- %s" % item)
                lines.append("")
            mitigations = getattr(attack_path, "recommended_mitigations", []) or []
            if mitigations:
                lines.append("**Recommended Mitigations:**")
                for item in mitigations:
                    lines.append("- %s" % item)
                lines.append("")
            related_findings = getattr(attack_path, "related_findings", []) or []
            if related_findings:
                lines.append(
                    "**Related Findings:** %s" % ", ".join(related_findings)
                )
                lines.append("")

    if report.recommended_fixes:
        lines.append("## Recommended Fixes")
        lines.append("")
        lines.append("| Priority | Layer | Title | Effort |")
        lines.append("|----------|-------|-------|--------|")
        for recommended_fix in sorted(
            report.recommended_fixes,
            key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                item.priority, 4
            ),
        ):
            lines.append(
                "| %s | %s | %s | %s |"
                % (
                    recommended_fix.priority,
                    recommended_fix.layer,
                    recommended_fix.title,
                    recommended_fix.effort,
                )
            )
        lines.append("")

    return "\n".join(lines)
