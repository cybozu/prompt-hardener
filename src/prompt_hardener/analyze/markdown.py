"""Render AnalyzeReport as Markdown."""

from prompt_hardener.analyze.report import AnalyzeReport


def render_markdown(report):
    # type: (AnalyzeReport) -> str
    """Convert an AnalyzeReport to a Markdown string."""
    lines = []

    # Title
    lines.append("# Prompt Hardener Analysis Report")
    lines.append("")

    # Metadata
    m = report.metadata
    lines.append("**Agent:** %s (type: %s)" % (m.agent_name, m.agent_type))
    lines.append("**Generated:** %s" % m.timestamp)
    lines.append("**Tool Version:** %s | **Rules Version:** %s | **Rules Evaluated:** %d" % (
        m.tool_version, m.rules_version, m.rules_evaluated
    ))
    lines.append("")

    # Summary
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

    # Findings
    if report.findings:
        lines.append("## Findings")
        lines.append("")
        for f in report.findings:
            lines.append("### %s: %s" % (f.rule_id, f.title))
            lines.append("")
            lines.append("- **Severity:** %s" % f.severity)
            lines.append("- **Layer:** %s" % f.layer)
            lines.append("- **Spec Path:** `%s`" % f.spec_path)
            lines.append("")
            lines.append(f.description)
            lines.append("")
            if f.evidence:
                lines.append("**Evidence:**")
                for e in f.evidence:
                    lines.append("- %s" % e)
                lines.append("")
            if f.recommendation:
                lines.append("**Recommendation:** %s" % f.recommendation)
                lines.append("")

    # Attack Paths
    if report.attack_paths:
        lines.append("## Attack Paths")
        lines.append("")
        for ap in report.attack_paths:
            lines.append("### %s" % ap.name)
            lines.append("")
            lines.append("- **Severity:** %s" % ap.severity)
            lines.append("")
            lines.append(ap.description)
            lines.append("")
            if ap.steps:
                lines.append("**Steps:**")
                for i, step in enumerate(ap.steps, 1):
                    lines.append("%d. %s" % (i, step))
                lines.append("")
            if ap.related_findings:
                lines.append("**Related Findings:** %s" % ", ".join(ap.related_findings))
                lines.append("")

    # Recommended Fixes
    if report.recommended_fixes:
        lines.append("## Recommended Fixes")
        lines.append("")
        lines.append("| Priority | Layer | Title | Effort |")
        lines.append("|----------|-------|-------|--------|")
        for rf in sorted(report.recommended_fixes, key=lambda x: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.priority, 4)
        )):
            lines.append("| %s | %s | %s | %s |" % (
                rf.priority, rf.layer, rf.title, rf.effort
            ))
        lines.append("")

    return "\n".join(lines)
