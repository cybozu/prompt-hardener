"""Report subcommand: render analyze/simulate/remediate JSON results as formatted reports."""

import html
import json

# ---------------------------------------------------------------------------
# Shared HTML styles (reused from gen_report.py pattern)
# ---------------------------------------------------------------------------

_HTML_STYLE = """\
body {
    font-family: Arial, sans-serif;
    padding: 30px;
    line-height: 1.6;
    color: #333;
    background-color: #fff;
}
h1 {
    background-color: #007acc;
    color: white;
    padding: 10px;
    border-radius: 5px;
}
h2 {
    color: #007acc;
    margin-top: 30px;
}
h3 {
    color: #005a99;
}
pre {
    background: #f4f4f4;
    padding: 10px;
    border-radius: 5px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}
.section {
    margin-bottom: 40px;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}
th, td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
}
th {
    background-color: #007acc;
    color: white;
}
.severity-critical { color: #d32f2f; font-weight: bold; }
.severity-high { color: #f57c00; font-weight: bold; }
.severity-medium { color: #fbc02d; font-weight: bold; }
.severity-low { color: #388e3c; }
.risk-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    color: white;
    font-weight: bold;
}
.risk-critical { background-color: #d32f2f; }
.risk-high { background-color: #f57c00; }
.risk-medium { background-color: #fbc02d; color: #333; }
.risk-low { background-color: #388e3c; }
"""


def _esc(text):
    # type: (Any) -> str
    """HTML-escape helper."""
    return html.escape(str(text))


def _md_table_text(text, max_len=60):
    # type: (Any, int) -> str
    """Normalize text for a single markdown table cell."""
    normalized = " ".join(str(text).splitlines()).replace("|", "\\|")
    if len(normalized) > max_len:
        return normalized[:max_len] + "..."
    return normalized


def _md_fenced_block(text):
    # type: (Any) -> str
    """Wrap arbitrary text in a fenced code block without breaking on backticks."""
    text = str(text)
    max_ticks = 0
    current_ticks = 0
    for char in text:
        if char == "`":
            current_ticks += 1
            if current_ticks > max_ticks:
                max_ticks = current_ticks
        else:
            current_ticks = 0
    fence = "`" * max(3, max_ticks + 1)
    return "%s\n%s\n%s" % (fence, text, fence)


def _severity_class(severity):
    # type: (str) -> str
    return "severity-%s" % severity


def _risk_badge_html(risk_level):
    # type: (str) -> str
    return '<span class="risk-badge risk-%s">%s</span>' % (
        risk_level,
        risk_level.upper(),
    )


# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------


def detect_result_type(data):
    # type: (Dict[str, Any]) -> str
    """Detect the result type from a JSON report dict.

    Returns "analyze", "simulate", or "remediate".
    Raises ValueError if the type cannot be determined.
    """
    if "simulation" in data:
        return "simulate"
    if "remediation" in data:
        return "remediate"
    if "findings" in data:
        return "analyze"
    raise ValueError(
        "Cannot detect result type: expected 'simulation', 'remediation', or 'findings' key in JSON"
    )


# ---------------------------------------------------------------------------
# Analyze renderers
# ---------------------------------------------------------------------------


def render_analyze_json(data):
    # type: (Dict[str, Any]) -> str
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_analyze_markdown(data):
    # type: (Dict[str, Any]) -> str
    lines = []

    lines.append("# Prompt Hardener Analysis Report")
    lines.append("")

    # Metadata
    m = data.get("metadata", {})
    lines.append(
        "**Agent:** %s (type: %s)" % (m.get("agent_name", ""), m.get("agent_type", ""))
    )
    lines.append("**Generated:** %s" % m.get("timestamp", ""))
    lines.append(
        "**Tool Version:** %s | **Rules Version:** %s | **Rules Evaluated:** %s"
        % (
            m.get("tool_version", ""),
            m.get("rules_version", ""),
            m.get("rules_evaluated", ""),
        )
    )
    lines.append("")

    # Summary
    s = data.get("summary", {})
    risk_level = s.get("risk_level", "unknown")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append("| Risk Level | **%s** |" % risk_level.upper())
    lines.append("| Overall Score | %.1f / 10.0 |" % s.get("overall_score", 0))
    for layer, score in sorted(s.get("scores_by_layer", {}).items()):
        lines.append("| %s Layer | %.1f / 10.0 |" % (layer.capitalize(), score))
    lines.append("")

    fc = s.get("finding_counts", {})
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
    findings = data.get("findings", [])
    if findings:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            lines.append("### %s: %s" % (f.get("rule_id", ""), f.get("title", "")))
            lines.append("")
            lines.append("- **Severity:** %s" % f.get("severity", ""))
            lines.append("- **Layer:** %s" % f.get("layer", ""))
            lines.append("- **Spec Path:** `%s`" % f.get("spec_path", ""))
            lines.append("")
            lines.append(f.get("description", ""))
            lines.append("")
            evidence = f.get("evidence", [])
            if evidence:
                lines.append("**Evidence:**")
                for e in evidence:
                    lines.append("- %s" % e)
                lines.append("")
            rec = f.get("recommendation", "")
            if rec:
                lines.append("**Recommendation:** %s" % rec)
                lines.append("")

    # Attack Paths
    attack_paths = data.get("attack_paths", [])
    if attack_paths:
        lines.append("## Attack Paths")
        lines.append("")
        for ap in attack_paths:
            lines.append("### %s" % ap.get("name", ""))
            lines.append("")
            lines.append("- **Severity:** %s" % ap.get("severity", ""))
            lines.append("")
            lines.append(ap.get("description", ""))
            lines.append("")
            steps = ap.get("steps", [])
            if steps:
                lines.append("**Steps:**")
                for i, step in enumerate(steps, 1):
                    lines.append("%d. %s" % (i, step))
                lines.append("")
            related = ap.get("related_findings", [])
            if related:
                lines.append("**Related Findings:** %s" % ", ".join(related))
                lines.append("")

    # Recommended Fixes
    fixes = data.get("recommended_fixes", [])
    if fixes:
        lines.append("## Recommended Fixes")
        lines.append("")
        lines.append("| Priority | Layer | Title | Effort |")
        lines.append("|----------|-------|-------|--------|")
        for rf in sorted(
            fixes,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                x.get("priority", ""), 4
            ),
        ):
            lines.append(
                "| %s | %s | %s | %s |"
                % (
                    rf.get("priority", ""),
                    rf.get("layer", ""),
                    rf.get("title", ""),
                    rf.get("effort", ""),
                )
            )
        lines.append("")

    return "\n".join(lines)


def render_analyze_html(data):
    # type: (Dict[str, Any]) -> str
    m = data.get("metadata", {})
    s = data.get("summary", {})
    risk_level = s.get("risk_level", "unknown")

    # Metadata table
    meta_html = (
        "<table>"
        "<tr><th>Field</th><th>Value</th></tr>"
        "<tr><td>Agent Name</td><td>%s</td></tr>"
        "<tr><td>Agent Type</td><td>%s</td></tr>"
        "<tr><td>Timestamp</td><td>%s</td></tr>"
        "<tr><td>Tool Version</td><td>%s</td></tr>"
        "<tr><td>Rules Version</td><td>%s</td></tr>"
        "<tr><td>Rules Evaluated</td><td>%s</td></tr>"
        "</table>"
    ) % (
        _esc(m.get("agent_name", "")),
        _esc(m.get("agent_type", "")),
        _esc(m.get("timestamp", "")),
        _esc(m.get("tool_version", "")),
        _esc(m.get("rules_version", "")),
        _esc(m.get("rules_evaluated", "")),
    )

    # Summary
    fc = s.get("finding_counts", {})
    summary_html = ("<p>Risk Level: %s</p><p>Overall Score: %.1f / 10.0</p>") % (
        _risk_badge_html(risk_level),
        s.get("overall_score", 0),
    )

    for layer, score in sorted(s.get("scores_by_layer", {}).items()):
        summary_html += "<p>%s Layer: %.1f / 10.0</p>" % (
            _esc(layer.capitalize()),
            score,
        )

    summary_html += "<p>Findings: %d total" % fc.get("total", 0)
    parts = []
    for sev in ["critical", "high", "medium", "low"]:
        count = fc.get(sev, 0)
        if count > 0:
            parts.append("%d %s" % (count, sev))
    if parts:
        summary_html += " (%s)" % ", ".join(parts)
    summary_html += "</p>"

    # Findings
    findings_html = ""
    for f in data.get("findings", []):
        evidence_html = ""
        for e in f.get("evidence", []):
            evidence_html += "<li>%s</li>" % _esc(e)
        if evidence_html:
            evidence_html = "<ul>%s</ul>" % evidence_html

        findings_html += (
            '<div class="section">'
            "<h3>%s: %s</h3>"
            '<p><span class="%s">Severity: %s</span> | Layer: %s | Spec Path: <code>%s</code></p>'
            "<p>%s</p>"
            "%s"
            "%s"
            "</div>"
        ) % (
            _esc(f.get("rule_id", "")),
            _esc(f.get("title", "")),
            _severity_class(f.get("severity", "")),
            _esc(f.get("severity", "")),
            _esc(f.get("layer", "")),
            _esc(f.get("spec_path", "")),
            _esc(f.get("description", "")),
            "<p><strong>Evidence:</strong></p>%s" % evidence_html
            if evidence_html
            else "",
            "<p><strong>Recommendation:</strong> %s</p>"
            % _esc(f.get("recommendation", ""))
            if f.get("recommendation")
            else "",
        )

    # Attack Paths
    attack_paths_html = ""
    for ap in data.get("attack_paths", []):
        steps_html = ""
        for step in ap.get("steps", []):
            steps_html += "<li>%s</li>" % _esc(step)
        if steps_html:
            steps_html = "<ol>%s</ol>" % steps_html

        attack_paths_html += (
            '<div class="section">'
            "<h3>%s</h3>"
            '<p><span class="%s">Severity: %s</span></p>'
            "<p>%s</p>"
            "%s"
            "</div>"
        ) % (
            _esc(ap.get("name", "")),
            _severity_class(ap.get("severity", "")),
            _esc(ap.get("severity", "")),
            _esc(ap.get("description", "")),
            steps_html,
        )

    # Recommended Fixes
    fixes_rows = ""
    for rf in sorted(
        data.get("recommended_fixes", []),
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            x.get("priority", ""), 4
        ),
    ):
        fixes_rows += (
            "<tr>"
            '<td><span class="%s">%s</span></td>'
            "<td>%s</td><td>%s</td><td>%s</td>"
            "</tr>"
        ) % (
            _severity_class(rf.get("priority", "")),
            _esc(rf.get("priority", "")),
            _esc(rf.get("layer", "")),
            _esc(rf.get("title", "")),
            _esc(rf.get("effort", "")),
        )
    fixes_html = ""
    if fixes_rows:
        fixes_html = (
            "<table>"
            "<tr><th>Priority</th><th>Layer</th><th>Title</th><th>Effort</th></tr>"
            "%s</table>"
        ) % fixes_rows

    return _wrap_html(
        "Prompt Hardener Analysis Report",
        (
            '<div class="section"><h2>Metadata</h2>%s</div>'
            '<div class="section"><h2>Summary</h2>%s</div>'
            '<div class="section"><h2>Findings</h2>%s</div>'
            '<div class="section"><h2>Attack Paths</h2>%s</div>'
            '<div class="section"><h2>Recommended Fixes</h2>%s</div>'
        )
        % (
            meta_html,
            summary_html,
            findings_html or "<p>No findings.</p>",
            attack_paths_html or "<p>No attack paths.</p>",
            fixes_html or "<p>No recommended fixes.</p>",
        ),
    )


# ---------------------------------------------------------------------------
# Simulate renderers
# ---------------------------------------------------------------------------


def render_simulate_json(data):
    # type: (Dict[str, Any]) -> str
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_simulate_markdown(data):
    # type: (Dict[str, Any]) -> str
    lines = []
    lines.append("# Prompt Hardener Simulation Report")
    lines.append("")

    # Metadata
    m = data.get("metadata", {})
    lines.append("**Agent Type:** %s" % m.get("agent_type", ""))
    lines.append("**Generated:** %s" % m.get("timestamp", ""))
    models = m.get("models", {})
    attack_m = models.get("attack", {})
    judge_m = models.get("judge", {})
    lines.append(
        "**Attack Model:** %s/%s | **Judge Model:** %s/%s"
        % (
            attack_m.get("api", ""),
            attack_m.get("model", ""),
            judge_m.get("api", ""),
            judge_m.get("model", ""),
        )
    )
    lines.append("")

    # Summary
    sim = data.get("simulation", {})
    s = sim.get("summary", {})
    top = data.get("summary", {})
    risk_level = top.get("risk_level", "unknown")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append("| Risk Level | **%s** |" % risk_level.upper())
    lines.append("| Total Scenarios | %d |" % s.get("total", 0))
    lines.append("| Blocked | %d |" % s.get("blocked", 0))
    lines.append("| Succeeded | %d |" % s.get("succeeded", 0))
    lines.append("| Block Rate | %.1f%% |" % (s.get("block_rate", 0) * 100))
    lines.append("")

    key_findings = top.get("key_findings", [])
    if key_findings:
        lines.append("**Key Findings:**")
        for kf in key_findings:
            lines.append("- %s" % kf)
        lines.append("")

    # Scenarios
    scenarios = sim.get("scenarios", [])
    if scenarios:
        lines.append("## Scenario Results")
        lines.append("")
        lines.append("| ID | Category | Layer | Outcome | Payload |")
        lines.append("|----|----------|-------|---------|---------|")
        for sc in scenarios:
            lines.append(
                "| %s | %s | %s | %s | %s |"
                % (
                    sc.get("id", ""),
                    sc.get("category", ""),
                    sc.get("target_layer", ""),
                    sc.get("outcome", ""),
                    _md_table_text(sc.get("payload", "")),
                )
            )
        lines.append("")

        # Details for succeeded scenarios
        succeeded = [sc for sc in scenarios if sc.get("outcome") == "SUCCEEDED"]
        if succeeded:
            lines.append("### Succeeded Attacks (Details)")
            lines.append("")
            for sc in succeeded:
                lines.append("**%s** (%s)" % (sc.get("id", ""), sc.get("category", "")))
                lines.append("")
                lines.append("**Payload:**")
                lines.append("")
                lines.append(_md_fenced_block(sc.get("payload", "")))
                lines.append("")
                lines.append("**Response:**")
                lines.append("")
                lines.append(_md_fenced_block(sc.get("response", "")))
                if sc.get("details"):
                    lines.append("")
                    lines.append("- **Details:** %s" % sc["details"])
                lines.append("")

    return "\n".join(lines)


def render_simulate_html(data):
    # type: (Dict[str, Any]) -> str
    m = data.get("metadata", {})
    sim = data.get("simulation", {})
    s = sim.get("summary", {})
    top = data.get("summary", {})
    risk_level = top.get("risk_level", "unknown")

    models = m.get("models", {})
    attack_m = models.get("attack", {})
    judge_m = models.get("judge", {})

    meta_html = (
        "<table>"
        "<tr><th>Field</th><th>Value</th></tr>"
        "<tr><td>Agent Type</td><td>%s</td></tr>"
        "<tr><td>Timestamp</td><td>%s</td></tr>"
        "<tr><td>Attack Model</td><td>%s / %s</td></tr>"
        "<tr><td>Judge Model</td><td>%s / %s</td></tr>"
        "</table>"
    ) % (
        _esc(m.get("agent_type", "")),
        _esc(m.get("timestamp", "")),
        _esc(attack_m.get("api", "")),
        _esc(attack_m.get("model", "")),
        _esc(judge_m.get("api", "")),
        _esc(judge_m.get("model", "")),
    )

    summary_html = (
        "<p>Risk Level: %s</p>"
        "<p>Total: %d | Blocked: %d | Succeeded: %d | Block Rate: %.1f%%</p>"
    ) % (
        _risk_badge_html(risk_level),
        s.get("total", 0),
        s.get("blocked", 0),
        s.get("succeeded", 0),
        s.get("block_rate", 0) * 100,
    )

    # Scenarios table
    rows = ""
    for sc in sim.get("scenarios", []):
        outcome = sc.get("outcome", "")
        outcome_style = "color: #388e3c;" if outcome == "BLOCKED" else "color: #d32f2f;"
        rows += (
            "<tr>"
            "<td>%s</td><td>%s</td><td>%s</td>"
            '<td style="%s"><strong>%s</strong></td>'
            '<td><pre style="margin:0;">%s</pre></td>'
            "</tr>"
        ) % (
            _esc(sc.get("id", "")),
            _esc(sc.get("category", "")),
            _esc(sc.get("target_layer", "")),
            outcome_style,
            _esc(outcome),
            _esc(sc.get("payload", "")),
        )

    scenarios_html = ""
    if rows:
        scenarios_html = (
            "<table>"
            "<tr><th>ID</th><th>Category</th><th>Layer</th><th>Outcome</th><th>Payload</th></tr>"
            "%s</table>"
        ) % rows

    return _wrap_html(
        "Prompt Hardener Simulation Report",
        (
            '<div class="section"><h2>Metadata</h2>%s</div>'
            '<div class="section"><h2>Summary</h2>%s</div>'
            '<div class="section"><h2>Scenario Results</h2>%s</div>'
        )
        % (meta_html, summary_html, scenarios_html or "<p>No scenarios.</p>"),
    )


# ---------------------------------------------------------------------------
# Remediate renderers
# ---------------------------------------------------------------------------


def render_remediate_json(data):
    # type: (Dict[str, Any]) -> str
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_remediate_markdown(data):
    # type: (Dict[str, Any]) -> str
    lines = []
    lines.append("# Prompt Hardener Remediation Report")
    lines.append("")

    # Metadata
    m = data.get("metadata", {})
    lines.append("**Agent Type:** %s" % m.get("agent_type", ""))
    lines.append("**Generated:** %s" % m.get("timestamp", ""))
    lines.append("**Layers:** %s" % ", ".join(m.get("layers", [])))
    lines.append("")

    # Summary
    top = data.get("summary", {})
    risk_level = top.get("risk_level", "unknown")
    lines.append("## Summary")
    lines.append("")
    lines.append("**Risk Level:** %s" % risk_level.upper())
    lines.append("")
    key_findings = top.get("key_findings", [])
    if key_findings:
        for kf in key_findings:
            lines.append("- %s" % kf)
        lines.append("")

    # Remediation details
    rem = data.get("remediation", {})

    # Prompt remediation
    prompt_rem = rem.get("prompt")
    if prompt_rem:
        lines.append("## Prompt Remediation")
        lines.append("")
        lines.append("**Changes:** %s" % prompt_rem.get("changes", ""))
        lines.append("")
        lines.append(
            "**Rewrite Applied:** %s"
            % ("yes" if prompt_rem.get("rewrite_applied") else "no")
        )
        lines.append("")
        if prompt_rem.get("no_op_reason"):
            lines.append("**No-op Reason:** %s" % prompt_rem.get("no_op_reason"))
            lines.append("")
        selected_techniques = prompt_rem.get("techniques_selected", [])
        if selected_techniques:
            lines.append("**Selected Techniques:**")
            for t in selected_techniques:
                lines.append("- %s" % t)
            lines.append("")
        techniques = prompt_rem.get("techniques_applied", [])
        if techniques:
            lines.append("**Applied Techniques:**")
            for t in techniques:
                lines.append("- %s" % t)
            lines.append("")
        addressed = prompt_rem.get("findings_addressed", [])
        if addressed:
            lines.append("**Findings Addressed:** %s" % ", ".join(addressed))
            lines.append("")
        deferred = prompt_rem.get("deferred_findings", [])
        if deferred:
            lines.append("**Deferred Findings:** %s" % ", ".join(deferred))
            lines.append("")
        notes = prompt_rem.get("change_notes", [])
        if notes:
            lines.append("**Change Notes:**")
            for note in notes:
                lines.append("- %s" % note)
            lines.append("")

    # Tool recommendations
    tool_rem = rem.get("tool")
    if tool_rem:
        recs = tool_rem.get("recommendations", [])
        if recs:
            lines.append("## Tool Recommendations")
            lines.append("")
            for r in recs:
                lines.append(
                    "### [%s] %s" % (r.get("severity", "").upper(), r.get("title", ""))
                )
                lines.append("")
                lines.append(r.get("description", ""))
                lines.append("")
                if r.get("suggested_change"):
                    lines.append("**Suggested Change:** %s" % r["suggested_change"])
                    lines.append("")

    # Architecture recommendations
    arch_rem = rem.get("architecture")
    if arch_rem:
        recs = arch_rem.get("recommendations", [])
        if recs:
            lines.append("## Architecture Recommendations")
            lines.append("")
            for r in recs:
                lines.append(
                    "### [%s] %s" % (r.get("severity", "").upper(), r.get("title", ""))
                )
                lines.append("")
                lines.append(r.get("description", ""))
                lines.append("")
                if r.get("suggested_change"):
                    lines.append("**Suggested Change:** %s" % r["suggested_change"])
                    lines.append("")

    return "\n".join(lines)


def render_remediate_html(data):
    # type: (Dict[str, Any]) -> str
    m = data.get("metadata", {})
    top = data.get("summary", {})
    risk_level = top.get("risk_level", "unknown")
    rem = data.get("remediation", {})

    meta_html = (
        "<table>"
        "<tr><th>Field</th><th>Value</th></tr>"
        "<tr><td>Agent Type</td><td>%s</td></tr>"
        "<tr><td>Timestamp</td><td>%s</td></tr>"
        "<tr><td>Layers</td><td>%s</td></tr>"
        "</table>"
    ) % (
        _esc(m.get("agent_type", "")),
        _esc(m.get("timestamp", "")),
        _esc(", ".join(m.get("layers", []))),
    )

    summary_html = "<p>Risk Level: %s</p>" % _risk_badge_html(risk_level)
    for kf in top.get("key_findings", []):
        summary_html += "<p>%s</p>" % _esc(kf)

    # Prompt remediation
    prompt_html = ""
    prompt_rem = rem.get("prompt")
    if prompt_rem:
        selected_techniques_html = ""
        for t in prompt_rem.get("techniques_selected", []):
            selected_techniques_html += "<li>%s</li>" % _esc(t)
        if selected_techniques_html:
            selected_techniques_html = "<ul>%s</ul>" % selected_techniques_html
        techniques_html = ""
        for t in prompt_rem.get("techniques_applied", []):
            techniques_html += "<li>%s</li>" % _esc(t)
        if techniques_html:
            techniques_html = "<ul>%s</ul>" % techniques_html
        change_notes_html = ""
        for note in prompt_rem.get("change_notes", []):
            change_notes_html += "<li>%s</li>" % _esc(note)
        if change_notes_html:
            change_notes_html = "<ul>%s</ul>" % change_notes_html
        prompt_html = (
            '<div class="section">'
            "<h2>Prompt Remediation</h2>"
            "<p><strong>Changes:</strong> %s</p>"
            "<p><strong>Rewrite Applied:</strong> %s</p>"
            "%s"
            "%s"
            "%s"
            "%s"
            "</div>"
        ) % (
            _esc(prompt_rem.get("changes", "")),
            _esc("yes" if prompt_rem.get("rewrite_applied") else "no"),
            "<p><strong>No-op Reason:</strong> %s</p>"
            % _esc(prompt_rem.get("no_op_reason"))
            if prompt_rem.get("no_op_reason")
            else "",
            "<p><strong>Selected Techniques:</strong></p>%s" % selected_techniques_html
            if selected_techniques_html
            else "",
            "<p><strong>Techniques Applied:</strong></p>%s" % techniques_html
            if techniques_html
            else "",
            "<p><strong>Change Notes:</strong></p>%s" % change_notes_html
            if change_notes_html
            else "",
        )

    # Recommendations helper
    def _render_rec_section(title, section_data):
        if not section_data:
            return ""
        recs = section_data.get("recommendations", [])
        if not recs:
            return ""
        rows = ""
        for r in recs:
            rows += (
                "<tr>"
                '<td><span class="%s">%s</span></td>'
                "<td>%s</td><td>%s</td><td>%s</td>"
                "</tr>"
            ) % (
                _severity_class(r.get("severity", "")),
                _esc(r.get("severity", "").upper()),
                _esc(r.get("title", "")),
                _esc(r.get("description", "")),
                _esc(r.get("suggested_change", "-")),
            )
        return (
            '<div class="section">'
            "<h2>%s</h2>"
            "<table>"
            "<tr><th>Severity</th><th>Title</th><th>Description</th><th>Suggested Change</th></tr>"
            "%s</table></div>"
        ) % (_esc(title), rows)

    tool_html = _render_rec_section("Tool Recommendations", rem.get("tool"))
    arch_html = _render_rec_section(
        "Architecture Recommendations", rem.get("architecture")
    )

    return _wrap_html(
        "Prompt Hardener Remediation Report",
        (
            '<div class="section"><h2>Metadata</h2>%s</div>'
            '<div class="section"><h2>Summary</h2>%s</div>'
            "%s%s%s"
        )
        % (meta_html, summary_html, prompt_html, tool_html, arch_html),
    )


# ---------------------------------------------------------------------------
# HTML wrapper
# ---------------------------------------------------------------------------


def _wrap_html(title, body_content):
    # type: (str, str) -> str
    return (
        "<html>\n<head>\n<style>\n%s\n</style>\n</head>\n<body>\n"
        "<h1>%s</h1>\n%s\n</body>\n</html>"
    ) % (_HTML_STYLE, _esc(title), body_content)


# ---------------------------------------------------------------------------
# Renderer dispatch
# ---------------------------------------------------------------------------

_RENDERERS = {
    ("analyze", "json"): render_analyze_json,
    ("analyze", "markdown"): render_analyze_markdown,
    ("analyze", "html"): render_analyze_html,
    ("simulate", "json"): render_simulate_json,
    ("simulate", "markdown"): render_simulate_markdown,
    ("simulate", "html"): render_simulate_html,
    ("remediate", "json"): render_remediate_json,
    ("remediate", "markdown"): render_remediate_markdown,
    ("remediate", "html"): render_remediate_html,
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def generate_report(results_path, output_format="markdown", output_path=None):
    # type: (str, str, str | None) -> str
    """Load a JSON result file, detect type, render in requested format, and optionally write to file.

    Returns the rendered output string.
    """
    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    result_type = detect_result_type(data)

    key = (result_type, output_format)
    renderer = _RENDERERS.get(key)
    if renderer is None:
        raise ValueError(
            "Unsupported format '%s' for result type '%s'"
            % (output_format, result_type)
        )

    output = renderer(data)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)

    return output
