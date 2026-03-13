"""Tests for the report module."""

import json
import os
import tempfile

import pytest

from prompt_hardener.report import (
    detect_result_type,
    generate_report,
    render_analyze_html,
    render_analyze_json,
    render_analyze_markdown,
    render_remediate_html,
    render_remediate_json,
    render_remediate_markdown,
    render_simulate_html,
    render_simulate_json,
    render_simulate_markdown,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(name):
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# =========================================================================
# detect_result_type
# =========================================================================


class TestDetectResultType:
    def test_detect_analyze(self):
        data = _load_fixture("analyze_result.json")
        assert detect_result_type(data) == "analyze"

    def test_detect_simulate(self):
        data = _load_fixture("simulate_result.json")
        assert detect_result_type(data) == "simulate"

    def test_detect_remediate(self):
        data = _load_fixture("remediate_result.json")
        assert detect_result_type(data) == "remediate"

    def test_invalid_data(self):
        with pytest.raises(ValueError, match="Cannot detect result type"):
            detect_result_type({"foo": "bar"})

    def test_empty_data(self):
        with pytest.raises(ValueError, match="Cannot detect result type"):
            detect_result_type({})


# =========================================================================
# Analyze rendering
# =========================================================================


class TestAnalyzeRendering:
    @pytest.fixture
    def data(self):
        return _load_fixture("analyze_result.json")

    def test_json(self, data):
        output = render_analyze_json(data)
        parsed = json.loads(output)
        assert parsed["metadata"]["agent_name"] == "Customer Support Agent"
        assert len(parsed["findings"]) == 4

    def test_markdown(self, data):
        output = render_analyze_markdown(data)
        assert "# Prompt Hardener Analysis Report" in output
        assert "Customer Support Agent" in output
        assert "HIGH" in output
        assert "## Findings" in output
        assert "PROMPT-001" in output
        assert "TOOL-003" in output
        assert "## Attack Paths" in output
        assert "## Recommended Fixes" in output
        assert "critical" in output

    def test_html(self, data):
        output = render_analyze_html(data)
        assert "<html>" in output
        assert "Prompt Hardener Analysis Report" in output
        assert "Customer Support Agent" in output
        assert "PROMPT-001" in output
        assert "severity-critical" in output
        assert "risk-high" in output

    def test_markdown_no_findings(self):
        data = {
            "metadata": {
                "agent_name": "Bot",
                "agent_type": "chatbot",
                "timestamp": "",
                "tool_version": "",
                "rules_version": "",
                "rules_evaluated": 0,
            },
            "summary": {
                "risk_level": "low",
                "overall_score": 9.5,
                "scores_by_layer": {},
                "finding_counts": {"total": 0},
            },
            "findings": [],
            "attack_paths": [],
            "recommended_fixes": [],
        }
        output = render_analyze_markdown(data)
        assert "# Prompt Hardener Analysis Report" in output
        assert "## Findings" not in output


# =========================================================================
# Simulate rendering
# =========================================================================


class TestSimulateRendering:
    @pytest.fixture
    def data(self):
        return _load_fixture("simulate_result.json")

    def test_json(self, data):
        output = render_simulate_json(data)
        parsed = json.loads(output)
        assert parsed["simulation"]["summary"]["total"] == 3

    def test_markdown(self, data):
        output = render_simulate_markdown(data)
        assert "# Prompt Hardener Simulation Report" in output
        assert "MEDIUM" in output
        assert "SC001" in output
        assert "BLOCKED" in output
        assert "SUCCEEDED" in output
        assert "Succeeded Attacks" in output
        assert "Block Rate" in output

    def test_markdown_escapes_multiline_payloads_in_table(self):
        data = {
            "metadata": {
                "agent_type": "agent",
                "timestamp": "2026-03-12T12:00:00Z",
                "models": {
                    "attack": {"api": "openai", "model": "gpt-4.1-mini"},
                    "judge": {"api": "openai", "model": "gpt-4.1-mini"},
                },
            },
            "simulation": {
                "summary": {
                    "total": 1,
                    "blocked": 1,
                    "succeeded": 0,
                    "block_rate": 1.0,
                },
                "scenarios": [
                    {
                        "id": "cross_agent_escalation",
                        "category": "cross_agent_escalation",
                        "target_layer": "architecture",
                        "payload": "line 1\nline 2 | line 3",
                        "response": "blocked",
                        "outcome": "BLOCKED",
                    }
                ],
            },
            "summary": {"risk_level": "low", "key_findings": []},
        }

        output = render_simulate_markdown(data)

        assert (
            "| cross_agent_escalation | cross_agent_escalation | architecture | BLOCKED | "
            "line 1 line 2 \\| line 3 |" in output
        )

    def test_html(self, data):
        output = render_simulate_html(data)
        assert "<html>" in output
        assert "Prompt Hardener Simulation Report" in output
        assert "SC001" in output
        assert "BLOCKED" in output
        assert "SUCCEEDED" in output


# =========================================================================
# Remediate rendering
# =========================================================================


class TestRemediateRendering:
    @pytest.fixture
    def data(self):
        return _load_fixture("remediate_result.json")

    def test_json(self, data):
        output = render_remediate_json(data)
        parsed = json.loads(output)
        assert "remediation" in parsed
        assert "prompt" in parsed["remediation"]

    def test_markdown(self, data):
        output = render_remediate_markdown(data)
        assert "# Prompt Hardener Remediation Report" in output
        assert "Prompt Remediation" in output
        assert "instruction_defense" in output
        assert "Tool Recommendations" in output
        assert "Architecture Recommendations" in output
        assert "CRITICAL" in output

    def test_html(self, data):
        output = render_remediate_html(data)
        assert "<html>" in output
        assert "Prompt Hardener Remediation Report" in output
        assert "Prompt Remediation" in output
        assert "severity-critical" in output

    def test_markdown_prompt_only(self):
        data = {
            "metadata": {
                "agent_type": "chatbot",
                "timestamp": "",
                "layers": ["prompt"],
            },
            "remediation": {
                "prompt": {
                    "changes": "Added security instructions",
                    "techniques_selected": ["spotlighting"],
                    "techniques_applied": ["spotlighting"],
                },
            },
            "summary": {"risk_level": "low", "key_findings": []},
        }
        output = render_remediate_markdown(data)
        assert "Prompt Remediation" in output
        assert "Selected Techniques" in output
        assert "Applied Techniques" in output
        assert "Tool Recommendations" not in output


# =========================================================================
# generate_report (integration)
# =========================================================================


class TestGenerateReport:
    def test_analyze_to_markdown(self):
        path = os.path.join(FIXTURES_DIR, "analyze_result.json")
        output = generate_report(path, "markdown")
        assert "# Prompt Hardener Analysis Report" in output

    def test_simulate_to_html(self):
        path = os.path.join(FIXTURES_DIR, "simulate_result.json")
        output = generate_report(path, "html")
        assert "<html>" in output
        assert "Simulation Report" in output

    def test_remediate_to_json(self):
        path = os.path.join(FIXTURES_DIR, "remediate_result.json")
        output = generate_report(path, "json")
        parsed = json.loads(output)
        assert "remediation" in parsed

    def test_write_to_file(self):
        path = os.path.join(FIXTURES_DIR, "analyze_result.json")
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmp_path = f.name
        try:
            output = generate_report(path, "markdown", output_path=tmp_path)
            with open(tmp_path, "r", encoding="utf-8") as f:
                written = f.read()
            assert written == output
            assert "# Prompt Hardener Analysis Report" in written
        finally:
            os.unlink(tmp_path)

    def test_write_html_to_file(self):
        path = os.path.join(FIXTURES_DIR, "simulate_result.json")
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp_path = f.name
        try:
            generate_report(path, "html", output_path=tmp_path)
            with open(tmp_path, "r", encoding="utf-8") as f:
                written = f.read()
            assert "<html>" in written
        finally:
            os.unlink(tmp_path)

    def test_invalid_file(self):
        with pytest.raises((ValueError, FileNotFoundError, OSError)):
            generate_report("/nonexistent/path.json", "json")

    def test_unsupported_format(self):
        path = os.path.join(FIXTURES_DIR, "analyze_result.json")
        with pytest.raises(ValueError, match="Unsupported format"):
            generate_report(path, "pdf")
