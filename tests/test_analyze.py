"""Tests for the analyze module: rules, scoring, engine, CLI, and examples."""

import json
import os
import subprocess
import sys
from unittest.mock import patch

import jsonschema
import pytest

from prompt_hardener.agent_spec import dict_to_agent_spec, load_yaml
from prompt_hardener.analyze.engine import run_analyze
from prompt_hardener.analyze.markdown import render_markdown
from prompt_hardener.analyze.report import (
    AnalyzeMetadata,
    AnalyzeReport,
    AnalyzeSummary,
    AttackPath,
    Finding,
    RecommendedFix,
)
from prompt_hardener.analyze.rules import _ensure_rules_loaded, get_rules
from prompt_hardener.analyze.rules.arch_rules import (
    check_hitl_missing,
    check_tool_result_boundary,
    check_untrusted_mcp_broad_access,
)
from prompt_hardener.analyze.rules.prompt_rules import (
    check_role_definition,
    check_secrets_protection,
    check_untrusted_data_boundary,
)
from prompt_hardener.analyze.rules.tool_rules import (
    check_broad_tool_permissions,
    check_sensitive_tool_approval,
)
from prompt_hardener.analyze.scoring import (
    compute_layer_score,
    compute_risk_level,
    compute_scores,
)
from prompt_hardener.models import AgentSpec, ProviderConfig

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")
SCHEMAS_DIR = os.path.join(os.path.dirname(__file__), "..", "schemas")


def _load_spec(filename):
    """Load a fixture spec and return AgentSpec."""
    path = os.path.join(FIXTURES_DIR, filename)
    data = load_yaml(path)
    return dict_to_agent_spec(data)


# =========================================================================
# Group 1: Rule Registry
# =========================================================================


class TestRuleRegistry:
    def test_ensure_rules_loaded(self):
        _ensure_rules_loaded()
        rules = get_rules()
        assert len(rules) >= 8  # All 8 rules

    def test_filter_by_agent_type_chatbot(self):
        _ensure_rules_loaded()
        rules = get_rules(agent_type="chatbot")
        # Chatbot should only get prompt rules
        for r in rules:
            assert "chatbot" in r.meta.applicable_types

    def test_filter_by_agent_type_agent(self):
        _ensure_rules_loaded()
        rules = get_rules(agent_type="agent")
        layers = set(r.meta.layer for r in rules)
        assert "prompt" in layers
        assert "tool" in layers

    def test_filter_by_layer(self):
        _ensure_rules_loaded()
        rules = get_rules(layers=["tool"])
        for r in rules:
            assert r.meta.layer == "tool"

    def test_filter_by_type_and_layer(self):
        _ensure_rules_loaded()
        rules = get_rules(agent_type="rag", layers=["prompt"])
        for r in rules:
            assert "rag" in r.meta.applicable_types
            assert r.meta.layer == "prompt"

    def test_all_rules_have_unique_ids(self):
        _ensure_rules_loaded()
        rules = get_rules()
        ids = [r.meta.id for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


# =========================================================================
# Group 2: Prompt Rules
# =========================================================================


class TestPromptRules:
    def test_prompt001_fires_on_untrusted_rag(self):
        spec = _load_spec("rag_insecure_spec.yaml")
        findings = check_untrusted_data_boundary(spec)
        assert len(findings) >= 1
        assert all(f.rule_id == "PROMPT-001" for f in findings)
        assert all(f.severity == "high" for f in findings)

    def test_prompt001_no_fire_chatbot(self):
        spec = _load_spec("chatbot_spec.yaml")
        findings = check_untrusted_data_boundary(spec)
        assert len(findings) == 0

    def test_prompt001_no_fire_trusted_only(self):
        """RAG with only trusted sources should not trigger."""
        data = load_yaml(os.path.join(FIXTURES_DIR, "rag_spec.yaml"))
        for ds in data["data_sources"]:
            ds["trust_level"] = "trusted"
        spec = dict_to_agent_spec(data)
        findings = check_untrusted_data_boundary(spec)
        assert len(findings) == 0

    def test_prompt002_fires_on_insecure_rag(self):
        spec = _load_spec("rag_insecure_spec.yaml")
        findings = check_secrets_protection(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "PROMPT-002"

    def test_prompt002_no_fire_with_protection(self):
        """Agent-basic example has 'Do not reveal' in system prompt."""
        path = os.path.join(EXAMPLES_DIR, "agent-basic", "agent_spec.yaml")
        data = load_yaml(path)
        spec = dict_to_agent_spec(data)
        findings = check_secrets_protection(spec)
        assert len(findings) == 0

    def test_prompt003_fires_on_short_prompt(self):
        spec = _load_spec("rag_insecure_spec.yaml")
        findings = check_role_definition(spec)
        # The insecure RAG has a very short prompt without clear role
        assert len(findings) == 1
        assert findings[0].rule_id == "PROMPT-003"

    def test_prompt003_no_fire_on_good_prompt(self):
        spec = _load_spec("chatbot_spec.yaml")
        findings = check_role_definition(spec)
        assert len(findings) == 0


# =========================================================================
# Group 3: Tool Rules
# =========================================================================


class TestToolRules:
    def test_tool001_fires_on_insecure_agent(self):
        spec = _load_spec("agent_insecure_spec.yaml")
        findings = check_sensitive_tool_approval(spec)
        assert len(findings) >= 2  # delete_account, send_email, transfer_funds
        assert all(f.rule_id == "TOOL-001" for f in findings)

    def test_tool001_no_fire_on_chatbot(self):
        spec = _load_spec("chatbot_spec.yaml")
        findings = check_sensitive_tool_approval(spec)
        assert len(findings) == 0

    def test_tool001_considers_escalation_rules(self):
        """Agent-basic has escalation rules, should reduce findings."""
        spec = _load_spec("agent_spec.yaml")
        findings = check_sensitive_tool_approval(spec)
        # agent_spec.yaml has "escalate_to_human" which matches escalation pattern
        # but the tools themselves (get_order_status, search_knowledge_base) are not sensitive
        assert len(findings) == 0

    def test_tool002_fires_on_insecure_agent(self):
        spec = _load_spec("agent_insecure_spec.yaml")
        findings = check_broad_tool_permissions(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "TOOL-002"

    def test_tool002_no_fire_with_allowed_actions(self):
        spec = _load_spec("agent_spec.yaml")
        findings = check_broad_tool_permissions(spec)
        assert len(findings) == 0


# =========================================================================
# Group 4: Architecture Rules
# =========================================================================


class TestArchRules:
    def test_arch001_fires_on_insecure_agent(self):
        spec = _load_spec("agent_insecure_spec.yaml")
        findings = check_hitl_missing(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "ARCH-001"

    def test_arch001_no_fire_with_escalation(self):
        spec = _load_spec("agent_spec.yaml")
        findings = check_hitl_missing(spec)
        assert len(findings) == 0

    def test_arch002_no_fire_on_restricted_mcp(self):
        spec = _load_spec("mcp_agent_spec.yaml")
        findings = check_untrusted_mcp_broad_access(spec)
        # mcp_agent_spec has allowed_tools for all servers
        assert len(findings) == 0

    def test_arch003_fires_on_insecure_agent(self):
        spec = _load_spec("agent_insecure_spec.yaml")
        findings = check_tool_result_boundary(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "ARCH-003"


# =========================================================================
# Group 5: Scoring
# =========================================================================


class TestScoring:
    def test_compute_layer_score_no_findings(self):
        assert compute_layer_score([]) == 10.0

    def test_compute_layer_score_with_findings(self):
        findings = [
            Finding(id="f1", rule_id="X", title="", severity="high",
                    layer="prompt", description=""),
            Finding(id="f2", rule_id="Y", title="", severity="medium",
                    layer="prompt", description=""),
        ]
        # 10.0 - 2.0 (high) - 1.0 (medium) = 7.0
        assert compute_layer_score(findings) == 7.0

    def test_compute_layer_score_floor_zero(self):
        findings = [
            Finding(id="f1", rule_id="X", title="", severity="critical",
                    layer="prompt", description=""),
            Finding(id="f2", rule_id="Y", title="", severity="critical",
                    layer="prompt", description=""),
            Finding(id="f3", rule_id="Z", title="", severity="critical",
                    layer="prompt", description=""),
            Finding(id="f4", rule_id="W", title="", severity="critical",
                    layer="prompt", description=""),
        ]
        # 10.0 - 12.0 = clamped to 0.0
        assert compute_layer_score(findings) == 0.0

    def test_risk_level_thresholds(self):
        assert compute_risk_level(10.0) == "low"
        assert compute_risk_level(8.0) == "low"
        assert compute_risk_level(7.9) == "medium"
        assert compute_risk_level(5.0) == "medium"
        assert compute_risk_level(4.9) == "high"
        assert compute_risk_level(2.0) == "high"
        assert compute_risk_level(1.9) == "critical"
        assert compute_risk_level(0.0) == "critical"

    def test_compute_scores_chatbot(self):
        findings = [
            Finding(id="f1", rule_id="PROMPT-002", title="", severity="medium",
                    layer="prompt", description=""),
        ]
        scores_by_layer, overall, risk = compute_scores(findings, "chatbot")
        assert "prompt" in scores_by_layer
        assert "tool" not in scores_by_layer
        assert scores_by_layer["prompt"] == 9.0
        assert overall == 9.0
        assert risk == "low"

    def test_compute_scores_agent(self):
        findings = [
            Finding(id="f1", rule_id="PROMPT-001", title="", severity="high",
                    layer="prompt", description=""),
            Finding(id="f2", rule_id="TOOL-001", title="", severity="high",
                    layer="tool", description=""),
            Finding(id="f3", rule_id="ARCH-001", title="", severity="high",
                    layer="architecture", description=""),
        ]
        scores_by_layer, overall, risk = compute_scores(findings, "agent")
        assert scores_by_layer["prompt"] == 8.0
        assert scores_by_layer["tool"] == 8.0
        assert scores_by_layer["architecture"] == 8.0
        assert overall == 8.0
        assert risk == "low"


# =========================================================================
# Group 6: Report Serialization
# =========================================================================


class TestReportSerialization:
    def _make_report(self):
        return AnalyzeReport(
            metadata=AnalyzeMetadata(
                tool_version="0.5.0",
                timestamp="2026-03-08T12:00:00Z",
                agent_name="Test Agent",
                agent_type="rag",
                spec_digest="sha256:abc123",
                rules_version="1.0",
                rules_evaluated=5,
            ),
            summary=AnalyzeSummary(
                risk_level="high",
                overall_score=4.5,
                scores_by_layer={"prompt": 6.0, "architecture": 3.0},
                finding_counts={"critical": 0, "high": 2, "medium": 1, "low": 0, "total": 3},
            ),
            findings=[
                Finding(
                    id="finding-001",
                    rule_id="PROMPT-001",
                    title="Test finding",
                    severity="high",
                    layer="prompt",
                    description="Test description",
                    evidence=["evidence 1"],
                    spec_path="data_sources[0]",
                    recommendation="Fix it",
                ),
            ],
            attack_paths=[
                AttackPath(
                    id="path-001",
                    name="Test attack path",
                    severity="high",
                    description="Attack description",
                    steps=["Step 1", "Step 2"],
                    related_findings=["finding-001"],
                ),
            ],
            recommended_fixes=[
                RecommendedFix(
                    id="fix-001",
                    finding_id="finding-001",
                    layer="prompt",
                    title="Fix title",
                    description="Fix description",
                    priority="high",
                    effort="low",
                ),
            ],
        )

    def test_to_dict_roundtrip(self):
        report = self._make_report()
        d = report.to_dict()
        assert d["metadata"]["tool_version"] == "0.5.0"
        assert d["summary"]["risk_level"] == "high"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["id"] == "finding-001"
        assert len(d["attack_paths"]) == 1
        assert len(d["recommended_fixes"]) == 1

    def test_to_dict_validates_against_schema(self):
        report = self._make_report()
        d = report.to_dict()
        schema_path = os.path.join(SCHEMAS_DIR, "analyze_report.schema.json")
        with open(schema_path, "r") as f:
            schema = json.load(f)
        jsonschema.validate(d, schema)  # Raises on invalid


# =========================================================================
# Group 7: Markdown Renderer
# =========================================================================


class TestMarkdownRenderer:
    def test_render_contains_key_sections(self):
        report = TestReportSerialization()._make_report()
        md = render_markdown(report)
        assert "# Prompt Hardener Analysis Report" in md
        assert "Test Agent" in md
        assert "## Summary" in md
        assert "## Findings" in md
        assert "PROMPT-001" in md
        assert "## Attack Paths" in md
        assert "## Recommended Fixes" in md


# =========================================================================
# Group 8: Engine Integration
# =========================================================================


class TestEngineIntegration:
    def test_run_analyze_rag_insecure(self):
        spec_path = os.path.join(FIXTURES_DIR, "rag_insecure_spec.yaml")
        report = run_analyze(spec_path)
        assert report.metadata.agent_type == "rag"
        assert report.summary.finding_counts["total"] >= 2
        rule_ids = [f.rule_id for f in report.findings]
        assert "PROMPT-001" in rule_ids

    def test_run_analyze_agent_insecure(self):
        spec_path = os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml")
        report = run_analyze(spec_path)
        assert report.metadata.agent_type == "agent"
        assert report.summary.finding_counts["total"] >= 3
        rule_ids = [f.rule_id for f in report.findings]
        assert "TOOL-001" in rule_ids or "ARCH-001" in rule_ids

    def test_run_analyze_output_validates_schema(self):
        spec_path = os.path.join(FIXTURES_DIR, "rag_insecure_spec.yaml")
        report = run_analyze(spec_path)
        d = report.to_dict()
        schema_path = os.path.join(SCHEMAS_DIR, "analyze_report.schema.json")
        with open(schema_path, "r") as f:
            schema = json.load(f)
        jsonschema.validate(d, schema)

    def test_run_analyze_with_layer_filter(self):
        spec_path = os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml")
        report = run_analyze(spec_path, layers=["prompt"])
        for f in report.findings:
            assert f.layer == "prompt"

    def test_run_analyze_chatbot_low_findings(self):
        spec_path = os.path.join(FIXTURES_DIR, "chatbot_spec.yaml")
        report = run_analyze(spec_path)
        # Chatbot with good prompts should have very few findings
        assert report.summary.finding_counts["total"] <= 2


# =========================================================================
# Group 9: Example-based Tests
# =========================================================================


class TestExampleAnalysis:
    def test_rag_internal_assistant(self):
        spec_path = os.path.join(EXAMPLES_DIR, "rag-internal-assistant", "agent_spec.yaml")
        report = run_analyze(spec_path)
        rule_ids = [f.rule_id for f in report.findings]
        # Has untrusted employee_uploads → PROMPT-001 expected
        assert "PROMPT-001" in rule_ids

    def test_agent_basic(self):
        spec_path = os.path.join(EXAMPLES_DIR, "agent-basic", "agent_spec.yaml")
        report = run_analyze(spec_path)
        # Agent-basic has good policies, should not have too many findings
        assert report.summary.finding_counts["total"] <= 4

    def test_chatbot_minimal(self):
        spec_path = os.path.join(EXAMPLES_DIR, "chatbot-minimal", "agent_spec.yaml")
        report = run_analyze(spec_path)
        # Chatbot should have minimal findings (maybe PROMPT-002)
        assert report.summary.finding_counts["total"] <= 2
        # No tool or arch findings
        for f in report.findings:
            assert f.layer == "prompt"


# =========================================================================
# Group 10: LLM Evaluation in Analyze
# =========================================================================


class TestLLMEvaluation:
    @patch("prompt_hardener.evaluate.evaluate_prompt")
    def test_run_analyze_with_eval_params(self, mock_eval):
        """When eval_api_mode/eval_model are set, prompt_evaluation is populated."""
        mock_eval.return_value = {
            "Spotlighting": {"Tag user inputs": {"satisfaction": 7}},
        }
        spec_path = os.path.join(FIXTURES_DIR, "chatbot_spec.yaml")
        report = run_analyze(
            spec_path,
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
        )
        assert report.prompt_evaluation is not None
        assert report.prompt_eval_score == 7.0
        mock_eval.assert_called_once()

    def test_run_analyze_without_eval_params(self):
        """When eval_api_mode is None, prompt_evaluation remains None."""
        spec_path = os.path.join(FIXTURES_DIR, "chatbot_spec.yaml")
        report = run_analyze(spec_path)
        assert report.prompt_evaluation is None
        assert report.prompt_eval_score is None

    @patch("prompt_hardener.evaluate.evaluate_prompt")
    def test_llm_eval_not_in_to_dict(self, mock_eval):
        """LLM evaluation results should NOT appear in to_dict() for schema compat."""
        mock_eval.return_value = {
            "Spotlighting": {"Tag user inputs": {"satisfaction": 8}},
        }
        spec_path = os.path.join(FIXTURES_DIR, "chatbot_spec.yaml")
        report = run_analyze(
            spec_path,
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
        )
        d = report.to_dict()
        assert "prompt_evaluation" not in d
        assert "prompt_eval_score" not in d
        # Validate against schema still passes
        schema_path = os.path.join(SCHEMAS_DIR, "analyze_report.schema.json")
        with open(schema_path, "r") as f:
            schema = json.load(f)
        jsonschema.validate(d, schema)

    def test_run_analyze_with_agent_spec_object(self):
        """run_analyze() accepts an AgentSpec object directly."""
        spec = AgentSpec(
            version="1.0",
            type="chatbot",
            name="Test Bot",
            system_prompt="You are a helpful assistant.",
            provider=ProviderConfig(api="openai", model="gpt-4o-mini"),
        )
        report = run_analyze(spec, layers=["prompt"])
        assert report.metadata.agent_name == "Test Bot"
        assert report.metadata.spec_digest == "N/A"

    @patch("prompt_hardener.evaluate.evaluate_prompt")
    def test_run_analyze_agent_spec_with_eval(self, mock_eval):
        """AgentSpec object + LLM evaluation works correctly."""
        mock_eval.return_value = {
            "Spotlighting": {"Tag user inputs": {"satisfaction": 6}},
        }
        spec = AgentSpec(
            version="1.0",
            type="chatbot",
            name="Test Bot",
            system_prompt="You are a helpful assistant.",
            provider=ProviderConfig(api="openai", model="gpt-4o-mini"),
        )
        report = run_analyze(
            spec,
            layers=["prompt"],
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
        )
        assert report.prompt_evaluation is not None
        assert report.prompt_eval_score == 6.0


# =========================================================================
# Group 11: CLI Integration
# =========================================================================


class TestCLIIntegration:
    def test_analyze_json_output(self):
        spec_path = os.path.join(FIXTURES_DIR, "rag_insecure_spec.yaml")
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "analyze", spec_path, "--format", "json",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        report = json.loads(result.stdout)
        assert "metadata" in report
        assert "summary" in report
        assert "findings" in report

    def test_analyze_markdown_output(self):
        spec_path = os.path.join(FIXTURES_DIR, "rag_insecure_spec.yaml")
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "analyze", spec_path, "--format", "markdown",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "# Prompt Hardener Analysis Report" in result.stdout

    def test_analyze_to_file(self, tmp_path):
        spec_path = os.path.join(FIXTURES_DIR, "rag_insecure_spec.yaml")
        output = tmp_path / "report.json"
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "analyze", spec_path, "-o", str(output), "--format", "json",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert output.exists()
        report = json.loads(output.read_text())
        assert "metadata" in report

    def test_analyze_with_layer_filter(self):
        spec_path = os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml")
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "analyze", spec_path, "--format", "json", "-l", "prompt",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        report = json.loads(result.stdout)
        for f in report["findings"]:
            assert f["layer"] == "prompt"

    def test_analyze_invalid_spec(self):
        invalid_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "invalid", "missing_version.yaml"
        )
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "analyze", invalid_path,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
