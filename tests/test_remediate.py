"""Tests for remediate subcommand: data models, layers, engine, CLI, and schema."""

import json
import os
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock, patch

import jsonschema
import pytest

from prompt_hardener.analyze.report import Finding
from prompt_hardener.models import (
    AgentSpec,
    McpServer,
    Policies,
    ProviderConfig,
    ToolDef,
    DataSource,
)
from prompt_hardener.remediate.arch_layer import remediate_architecture
from prompt_hardener.remediate.report import (
    PromptRemediation,
    Recommendation,
    RemediationReport,
)
from prompt_hardener.remediate.tool_layer import remediate_tool
from prompt_hardener.schema import PromptInput

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SCHEMAS_DIR = os.path.join(os.path.dirname(__file__), "..", "schemas")


# =========================================================================
# Helper: Build AgentSpec for testing
# =========================================================================

def _make_spec(
    agent_type="agent",
    tools=None,
    policies=None,
    mcp_servers=None,
    data_sources=None,
    system_prompt="You are a helpful assistant.",
):
    return AgentSpec(
        version="1.0",
        type=agent_type,
        name="Test Agent",
        system_prompt=system_prompt,
        provider=ProviderConfig(api="openai", model="gpt-4o-mini"),
        tools=tools,
        policies=policies,
        mcp_servers=mcp_servers,
        data_sources=data_sources,
        user_input_description="User chat input",
    )


# =========================================================================
# Group 1: Data Models
# =========================================================================


class TestRecommendation:
    def test_basic_construction(self):
        r = Recommendation(
            severity="high",
            title="Add policies",
            description="Missing policies section",
        )
        assert r.severity == "high"
        assert r.suggested_change is None

    def test_to_dict_minimal(self):
        r = Recommendation(
            severity="medium",
            title="Test",
            description="Test desc",
        )
        d = r.to_dict()
        assert d["severity"] == "medium"
        assert d["title"] == "Test"
        assert d["description"] == "Test desc"
        assert "suggested_change" not in d

    def test_to_dict_with_suggested_change(self):
        r = Recommendation(
            severity="low",
            title="Add allowlist",
            description="No allowlist",
            suggested_change="policies:\n  allowed_actions: [tool1]",
        )
        d = r.to_dict()
        assert "suggested_change" in d
        assert "allowed_actions" in d["suggested_change"]


class TestPromptRemediation:
    def test_basic_construction(self):
        pr = PromptRemediation(
            changes="Improved prompt in 2 iterations",
            techniques_applied=["spotlighting", "role_consistency"],
        )
        assert "2 iterations" in pr.changes
        assert len(pr.techniques_applied) == 2

    def test_to_dict(self):
        pr = PromptRemediation(
            changes="No changes",
            techniques_applied=["instruction_defense"],
        )
        d = pr.to_dict()
        assert d["changes"] == "No changes"
        assert d["techniques_applied"] == ["instruction_defense"]

    def test_default_empty_techniques(self):
        pr = PromptRemediation(changes="test")
        assert pr.techniques_applied == []
        assert pr.to_dict()["techniques_applied"] == []


class TestRemediationReport:
    def test_empty_report(self):
        report = RemediationReport(metadata={
            "tool_version": "0.5.0",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "agent_type": "chatbot",
        })
        d = report.to_dict()
        assert "metadata" in d
        assert "remediation" in d
        assert "summary" in d
        assert d["remediation"] == {}

    def test_report_with_prompt_only(self):
        report = RemediationReport(
            metadata={"tool_version": "0.5.0", "timestamp": "t", "agent_type": "chatbot"},
            prompt=PromptRemediation(changes="improved", techniques_applied=["spotlighting"]),
        )
        d = report.to_dict()
        assert "prompt" in d["remediation"]
        assert "tool" not in d["remediation"]
        assert "architecture" not in d["remediation"]

    def test_report_with_all_layers(self):
        report = RemediationReport(
            metadata={"tool_version": "0.5.0", "timestamp": "t", "agent_type": "agent"},
            prompt=PromptRemediation(changes="improved", techniques_applied=["spotlighting"]),
            tool=[Recommendation(severity="high", title="T1", description="D1")],
            architecture=[Recommendation(severity="medium", title="T2", description="D2")],
        )
        d = report.to_dict()
        assert "prompt" in d["remediation"]
        assert "tool" in d["remediation"]
        assert "architecture" in d["remediation"]
        assert len(d["remediation"]["tool"]["recommendations"]) == 1
        assert len(d["remediation"]["architecture"]["recommendations"]) == 1

    def test_summary_risk_level_from_recommendations(self):
        report = RemediationReport(
            metadata={"tool_version": "0.5.0", "timestamp": "t", "agent_type": "agent"},
            tool=[Recommendation(severity="critical", title="T", description="D")],
        )
        d = report.to_dict()
        assert d["summary"]["risk_level"] == "critical"

    def test_summary_risk_level_low_when_no_recommendations(self):
        report = RemediationReport(
            metadata={"tool_version": "0.5.0", "timestamp": "t", "agent_type": "chatbot"},
            prompt=PromptRemediation(changes="ok", techniques_applied=[]),
        )
        d = report.to_dict()
        assert d["summary"]["risk_level"] == "low"


# =========================================================================
# Group 2: Tool Layer
# =========================================================================


class TestToolLayer:
    def test_insecure_spec_generates_recommendations(self):
        """Agent with tools but no policies should get recommendations."""
        spec = _make_spec(
            tools=[
                ToolDef(name="delete_account", description="Delete a user account"),
                ToolDef(name="get_balance", description="Get balance"),
            ],
            policies=None,
        )
        findings = [
            Finding(
                id="f1", rule_id="TOOL-001", title="No policies",
                severity="high", layer="tool",
                description="No tool usage policies defined",
                recommendation="Add policies section",
            ),
        ]
        recs = remediate_tool(spec, findings)
        assert len(recs) >= 2  # At least the finding + proactive "define policies"
        severities = [r.severity for r in recs]
        assert "high" in severities

    def test_chatbot_no_tools_minimal(self):
        """Chatbot without tools should get minimal/no recommendations."""
        spec = _make_spec(agent_type="chatbot", tools=None, policies=None)
        findings = []
        recs = remediate_tool(spec, findings)
        # No tools, so "define policies" is the only proactive one
        assert len(recs) >= 1
        # But no tool-specific recs
        tool_specific = [r for r in recs if "allowlist" in r.title.lower()]
        assert len(tool_specific) == 0

    def test_secure_spec_minimal_recommendations(self):
        """Spec with tools and full policies should have fewer recommendations."""
        spec = _make_spec(
            tools=[
                ToolDef(name="search", description="Search docs"),
            ],
            policies=Policies(
                allowed_actions=["search"],
                denied_actions=["delete_all"],
                escalation_rules=[],  # empty but present
            ),
        )
        findings = []
        recs = remediate_tool(spec, findings)
        # Should still have escalation_rules recommendation since it's empty
        assert any("escalation" in r.title.lower() for r in recs)

    def test_findings_from_other_layers_ignored(self):
        """Only tool-layer findings are converted."""
        spec = _make_spec(tools=None, policies=None)
        findings = [
            Finding(
                id="f1", rule_id="PROMPT-001", title="Prompt issue",
                severity="high", layer="prompt",
                description="Prompt problem",
            ),
            Finding(
                id="f2", rule_id="ARCH-001", title="Arch issue",
                severity="medium", layer="architecture",
                description="Arch problem",
            ),
        ]
        recs = remediate_tool(spec, findings)
        # None of the findings should appear as recommendations (wrong layer)
        finding_titles = {"Prompt issue", "Arch issue"}
        rec_titles = {r.title for r in recs}
        assert not finding_titles.intersection(rec_titles)

    def test_dangerous_tool_detection(self):
        """Tools with dangerous-looking names trigger denied_actions recommendation."""
        spec = _make_spec(
            tools=[
                ToolDef(name="transfer_funds", description="Transfer money"),
                ToolDef(name="read_file", description="Read a file"),
            ],
            policies=Policies(
                allowed_actions=["transfer_funds", "read_file"],
                # No denied_actions
            ),
        )
        findings = []
        recs = remediate_tool(spec, findings)
        denied_recs = [r for r in recs if "denied_actions" in r.title.lower()]
        assert len(denied_recs) == 1
        assert "transfer_funds" in denied_recs[0].description


# =========================================================================
# Group 3: Architecture Layer
# =========================================================================


class TestArchLayer:
    def test_agent_without_escalation_gets_hitl_recommendation(self):
        """Agent without escalation rules should get HITL recommendation."""
        spec = _make_spec(agent_type="agent", tools=[
            ToolDef(name="tool1", description="d"),
        ])
        findings = []
        recs = remediate_architecture(spec, findings)
        hitl_recs = [r for r in recs if "human-in-the-loop" in r.title.lower()]
        assert len(hitl_recs) == 1

    def test_agent_with_escalation_no_hitl(self):
        """Agent with escalation rules should NOT get HITL recommendation."""
        from prompt_hardener.models import EscalationRule
        spec = _make_spec(
            agent_type="agent",
            tools=[ToolDef(name="tool1", description="d")],
            policies=Policies(
                escalation_rules=[EscalationRule(condition="c", action="a")],
            ),
        )
        findings = []
        recs = remediate_architecture(spec, findings)
        hitl_recs = [r for r in recs if "human-in-the-loop" in r.title.lower()]
        assert len(hitl_recs) == 0

    def test_mcp_untrusted_server_no_allowed_tools(self):
        """Untrusted MCP server without allowed_tools gets recommendation."""
        spec = _make_spec(
            agent_type="mcp-agent",
            tools=[ToolDef(name="tool1", description="d")],
            mcp_servers=[
                McpServer(name="untrusted_server", trust_level="untrusted"),
            ],
        )
        findings = []
        recs = remediate_architecture(spec, findings)
        allowed_recs = [r for r in recs if "allowed_tools" in r.title.lower()]
        assert len(allowed_recs) >= 1

    def test_mcp_untrusted_server_sanitization(self):
        """Untrusted MCP server always gets output sanitization recommendation."""
        spec = _make_spec(
            agent_type="mcp-agent",
            tools=[ToolDef(name="tool1", description="d")],
            mcp_servers=[
                McpServer(
                    name="web_api",
                    trust_level="untrusted",
                    allowed_tools=["search"],
                ),
            ],
        )
        findings = []
        recs = remediate_architecture(spec, findings)
        sanitize_recs = [r for r in recs if "sanitize" in r.title.lower()]
        assert len(sanitize_recs) >= 1

    def test_mcp_trusted_server_no_extra_recs(self):
        """Trusted MCP server should not trigger MCP-specific recommendations."""
        spec = _make_spec(
            agent_type="mcp-agent",
            tools=[ToolDef(name="tool1", description="d")],
            mcp_servers=[
                McpServer(name="trusted_server", trust_level="trusted"),
            ],
        )
        findings = []
        recs = remediate_architecture(spec, findings)
        mcp_recs = [r for r in recs if "mcp" in r.title.lower() or "sanitize" in r.title.lower()]
        assert len(mcp_recs) == 0

    def test_findings_converted(self):
        """Architecture-layer findings are converted to recommendations."""
        spec = _make_spec(agent_type="chatbot")
        findings = [
            Finding(
                id="f1", rule_id="ARCH-001", title="Missing boundary",
                severity="high", layer="architecture",
                description="No data boundaries",
                recommendation="Add data boundaries",
            ),
        ]
        recs = remediate_architecture(spec, findings)
        assert any(r.title == "Missing boundary" for r in recs)

    def test_agent_with_many_tools_gets_separation_recommendation(self):
        """Agent with many tools should get model separation recommendation."""
        spec = _make_spec(
            agent_type="agent",
            tools=[ToolDef(name="t%d" % i, description="d") for i in range(5)],
        )
        findings = []
        recs = remediate_architecture(spec, findings)
        sep_recs = [r for r in recs if "model separation" in r.title.lower()]
        assert len(sep_recs) == 1

    def test_rag_untrusted_sources_boundary_recommendation(self):
        """RAG with untrusted sources and no boundary mention gets recommendation."""
        spec = _make_spec(
            agent_type="rag",
            data_sources=[
                DataSource(name="web_docs", type="api", trust_level="untrusted"),
            ],
            system_prompt="You are a helpful assistant. Answer questions.",
        )
        findings = []
        recs = remediate_architecture(spec, findings)
        boundary_recs = [r for r in recs if "boundary" in r.title.lower()]
        assert len(boundary_recs) >= 1


# =========================================================================
# Group 4: Prompt Layer (mocked)
# =========================================================================


class TestPromptLayer:
    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_iterative_loop(self, mock_eval, mock_improve):
        """Test that evaluate/improve loop runs correct number of iterations."""
        from prompt_hardener.remediate.prompt_layer import remediate_prompt

        # Evaluation returns scores below threshold
        mock_eval.return_value = {
            "Spotlighting": {"Tag user inputs": {"satisfaction": 5}},
        }
        mock_improve.return_value = PromptInput(
            mode="chat",
            messages=[{"role": "system", "content": "Improved prompt"}],
            messages_format="openai",
        )

        spec = _make_spec(agent_type="chatbot")
        remediation, improved = remediate_prompt(
            spec=spec,
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            max_iterations=3,
            threshold=8.5,
        )

        assert isinstance(remediation, PromptRemediation)
        assert "iteration" in remediation.changes.lower()
        # evaluate called: 1 initial + (max_iterations-1) in-loop + 1 final = max_iterations + 1
        assert mock_eval.call_count >= 2
        assert mock_improve.call_count == 3

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_threshold_reached_early(self, mock_eval, mock_improve):
        """Test that loop stops when threshold is reached."""
        from prompt_hardener.remediate.prompt_layer import remediate_prompt

        # First eval returns low score, second returns above threshold
        mock_eval.side_effect = [
            {"Spotlighting": {"sub": {"satisfaction": 5}}},
            {"Spotlighting": {"sub": {"satisfaction": 9}}},
        ]
        mock_improve.return_value = PromptInput(
            mode="chat",
            messages=[{"role": "system", "content": "Improved prompt"}],
            messages_format="openai",
        )

        spec = _make_spec(agent_type="chatbot")
        remediation, improved = remediate_prompt(
            spec=spec,
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            max_iterations=5,
            threshold=8.5,
        )

        # Should stop early: 1 improve in iter 0, eval in iter 1 meets threshold
        assert mock_improve.call_count == 1
        assert mock_eval.call_count == 2

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_system_prompt_extraction_openai(self, mock_eval, mock_improve):
        """Test system prompt extraction from OpenAI-format PromptInput."""
        from prompt_hardener.remediate.prompt_layer import remediate_prompt

        mock_eval.return_value = {
            "Spotlighting": {"sub": {"satisfaction": 9}},
        }
        improved_messages = [{"role": "system", "content": "New secure prompt"}]
        mock_improve.return_value = PromptInput(
            mode="chat",
            messages=improved_messages,
            messages_format="openai",
        )

        spec = _make_spec(agent_type="chatbot")
        remediation, improved = remediate_prompt(
            spec=spec,
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            max_iterations=1,
        )

        assert improved == "New secure prompt"

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_system_prompt_extraction_claude(self, mock_eval, mock_improve):
        """Test system prompt extraction from Claude-format PromptInput."""
        from prompt_hardener.remediate.prompt_layer import remediate_prompt

        mock_eval.return_value = {
            "Spotlighting": {"sub": {"satisfaction": 9}},
        }
        mock_improve.return_value = PromptInput(
            mode="chat",
            messages=[],
            messages_format="claude",
            system_prompt="New secure Claude prompt",
        )

        spec = _make_spec(
            agent_type="chatbot",
            system_prompt="Old prompt",
        )
        spec.provider = ProviderConfig(api="claude", model="claude-sonnet-4-20250514")

        remediation, improved = remediate_prompt(
            spec=spec,
            eval_api_mode="claude",
            eval_model="claude-sonnet-4-20250514",
            max_iterations=1,
        )

        assert improved == "New secure Claude prompt"

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_techniques_applied_in_remediation(self, mock_eval, mock_improve):
        """Test that specified techniques are recorded in remediation."""
        from prompt_hardener.remediate.prompt_layer import remediate_prompt

        mock_eval.return_value = {
            "Spotlighting": {"sub": {"satisfaction": 9}},
        }
        mock_improve.return_value = PromptInput(
            mode="chat",
            messages=[{"role": "system", "content": "improved"}],
            messages_format="openai",
        )

        spec = _make_spec(agent_type="chatbot")
        remediation, _ = remediate_prompt(
            spec=spec,
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            max_iterations=1,
            apply_techniques=["spotlighting", "role_consistency"],
        )

        assert remediation.techniques_applied == ["spotlighting", "role_consistency"]


# =========================================================================
# Group 5: Engine Integration (mocked prompt layer)
# =========================================================================


class TestEngine:
    @patch("prompt_hardener.remediate.engine.remediate_prompt")
    def test_run_remediate_all_layers(self, mock_prompt):
        """Test full remediation with all layers."""
        from prompt_hardener.remediate.engine import run_remediate

        mock_prompt.return_value = (
            PromptRemediation(changes="improved", techniques_applied=["spotlighting"]),
            "New prompt",
        )

        report = run_remediate(
            spec_path=os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
        )

        assert isinstance(report, RemediationReport)
        assert report.prompt is not None
        assert report.tool is not None
        assert report.architecture is not None

    def test_run_remediate_tool_only(self):
        """Test remediation with only tool layer (no LLM needed)."""
        from prompt_hardener.remediate.engine import run_remediate

        report = run_remediate(
            spec_path=os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            layers=["tool"],
        )

        assert report.prompt is None
        assert report.tool is not None
        assert report.architecture is None
        assert len(report.tool) > 0

    def test_run_remediate_architecture_only(self):
        """Test remediation with only architecture layer."""
        from prompt_hardener.remediate.engine import run_remediate

        report = run_remediate(
            spec_path=os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            layers=["architecture"],
        )

        assert report.prompt is None
        assert report.tool is None
        assert report.architecture is not None

    def test_run_remediate_tool_and_architecture(self):
        """Test remediation with tool + architecture (no LLM needed)."""
        from prompt_hardener.remediate.engine import run_remediate

        report = run_remediate(
            spec_path=os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            layers=["tool", "architecture"],
        )

        assert report.prompt is None
        assert report.tool is not None
        assert report.architecture is not None

    def test_run_remediate_invalid_spec(self):
        """Invalid spec path raises ValueError."""
        from prompt_hardener.remediate.engine import run_remediate

        with pytest.raises(ValueError, match="File not found"):
            run_remediate(
                spec_path="/nonexistent/path.yaml",
                eval_api_mode="openai",
                eval_model="gpt-4o-mini",
            )

    def test_run_remediate_chatbot_defaults_to_prompt_only(self):
        """Chatbot type should default to prompt layer only."""
        from prompt_hardener.remediate.engine import run_remediate

        with patch("prompt_hardener.remediate.engine.remediate_prompt") as mock_prompt:
            mock_prompt.return_value = (
                PromptRemediation(changes="ok", techniques_applied=[]),
                "New prompt",
            )
            report = run_remediate(
                spec_path=os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"),
                eval_api_mode="openai",
                eval_model="gpt-4o-mini",
            )

        assert report.prompt is not None
        assert report.tool is None
        assert report.architecture is None

    @patch("prompt_hardener.remediate.engine.remediate_prompt")
    def test_run_remediate_output_path(self, mock_prompt):
        """Test that output_path writes updated spec."""
        from prompt_hardener.remediate.engine import run_remediate

        mock_prompt.return_value = (
            PromptRemediation(changes="ok", techniques_applied=[]),
            "New improved system prompt",
        )

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            output_path = f.name

        try:
            run_remediate(
                spec_path=os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"),
                eval_api_mode="openai",
                eval_model="gpt-4o-mini",
                output_path=output_path,
            )

            assert os.path.exists(output_path)
            import yaml
            with open(output_path, "r") as f:
                data = yaml.safe_load(f)
            assert data["system_prompt"] == "New improved system prompt"
            assert data["type"] == "chatbot"
        finally:
            os.unlink(output_path)

    def test_run_remediate_metadata(self):
        """Verify metadata fields are populated."""
        from prompt_hardener.remediate.engine import run_remediate

        report = run_remediate(
            spec_path=os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            layers=["tool"],
        )

        assert report.metadata["tool_version"] == "0.5.0"
        assert "timestamp" in report.metadata
        assert report.metadata["agent_type"] == "agent"
        assert "agent_spec_digest" in report.metadata


# =========================================================================
# Group 6: CLI Integration
# =========================================================================


class TestCLIIntegration:
    def test_remediate_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "prompt_hardener.main", "remediate", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "remediate" in result.stdout
        assert "spec_path" in result.stdout
        assert "--eval-api-mode" in result.stdout
        assert "--layers" in result.stdout
        assert "--max-iterations" in result.stdout
        assert "--threshold" in result.stdout

    def test_remediate_missing_required_args(self):
        result = subprocess.run(
            [sys.executable, "-m", "prompt_hardener.main", "remediate"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    def test_remediate_missing_model_args(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "prompt_hardener.main",
                "remediate",
                os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    def test_remediate_tool_layer_only_no_llm(self):
        """Running with --layers tool architecture should not require LLM calls."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "prompt_hardener.main",
                "remediate",
                os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml"),
                "--layers", "tool", "architecture",
                "-ea", "openai",
                "-em", "gpt-4o-mini",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Remediation Summary" in result.stdout
        assert "Tool:" in result.stdout
        assert "Architecture:" in result.stdout


# =========================================================================
# Group 7: Schema Drift Guard
# =========================================================================


class TestSchemaDriftGuard:
    """Ensure RemediationReport.to_dict() output conforms to report.schema.json."""

    @staticmethod
    def _build_sample_report():
        return RemediationReport(
            metadata={
                "tool_version": "0.5.0",
                "timestamp": "2025-01-01T00:00:00+00:00",
                "agent_type": "agent",
            },
            prompt=PromptRemediation(
                changes="Improved in 2 iterations. Score: 5.0 -> 9.0.",
                techniques_applied=["spotlighting", "instruction_defense"],
            ),
            tool=[
                Recommendation(
                    severity="high",
                    title="Define policies",
                    description="No policies defined",
                    suggested_change="policies:\n  allowed_actions: [tool1]",
                ),
                Recommendation(
                    severity="medium",
                    title="Add denied_actions",
                    description="Missing denied_actions",
                ),
            ],
            architecture=[
                Recommendation(
                    severity="high",
                    title="Implement HITL controls",
                    description="No escalation rules",
                ),
            ],
        )

    def test_report_validates_against_schema(self):
        report = self._build_sample_report()
        report_dict = report.to_dict()

        schema_path = os.path.join(SCHEMAS_DIR, "report.schema.json")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        validator = jsonschema.Draft202012Validator(schema)
        errors = list(validator.iter_errors(report_dict))
        if errors:
            messages = []
            for err in errors:
                path = ".".join(str(p) for p in err.absolute_path) or "(root)"
                messages.append("at '%s': %s" % (path, err.message))
            pytest.fail(
                "Report does not conform to report.schema.json:\n  "
                + "\n  ".join(messages)
            )

    def test_recommendation_required_fields(self):
        """Verify Recommendation.to_dict() includes all required fields from schema."""
        schema_path = os.path.join(SCHEMAS_DIR, "report.schema.json")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        required_fields = schema["$defs"]["recommendation"]["required"]
        r = Recommendation(severity="high", title="T", description="D")
        d = r.to_dict()
        for field_name in required_fields:
            assert field_name in d, "Missing required field: %s" % field_name

    def test_prompt_remediation_matches_schema(self):
        """Verify PromptRemediation only has fields allowed by schema."""
        schema_path = os.path.join(SCHEMAS_DIR, "report.schema.json")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        allowed_fields = set(
            schema["properties"]["remediation"]["properties"]["prompt"]["properties"].keys()
        )
        pr = PromptRemediation(changes="test", techniques_applied=["x"])
        d = pr.to_dict()
        for key in d:
            assert key in allowed_fields, "Unexpected field in prompt remediation: %s" % key

    def test_report_serializable_as_json(self):
        report = self._build_sample_report()
        json_str = json.dumps(report.to_dict(), ensure_ascii=False)
        parsed = json.loads(json_str)
        assert "remediation" in parsed
        assert len(parsed["remediation"]["tool"]["recommendations"]) == 2


# =========================================================================
# Group 8: average_satisfaction utility
# =========================================================================


class TestAverageSatisfaction:
    def test_import_from_utils(self):
        """Verify average_satisfaction is importable from utils."""
        from prompt_hardener.utils import average_satisfaction
        assert callable(average_satisfaction)

    def test_import_from_main(self):
        """Verify main.py imports from utils (no local definition)."""
        import prompt_hardener.main as main_mod
        # average_satisfaction should be available as an imported name
        assert hasattr(main_mod, "average_satisfaction")

    def test_basic_calculation(self):
        from prompt_hardener.utils import average_satisfaction
        evaluation = {
            "Category1": {
                "sub1": {"satisfaction": 8},
                "sub2": {"satisfaction": 6},
            },
        }
        result = average_satisfaction(evaluation)
        assert result == 7.0

    def test_skips_critique_and_recommendation(self):
        from prompt_hardener.utils import average_satisfaction
        evaluation = {
            "Category1": {"sub1": {"satisfaction": 10}},
            "critique": {"text": "good"},
            "recommendation": {"text": "none"},
        }
        result = average_satisfaction(evaluation)
        assert result == 10.0

    def test_empty_returns_zero(self):
        from prompt_hardener.utils import average_satisfaction
        assert average_satisfaction({}) == 0.0


# =========================================================================
# Group 9: write_updated_spec
# =========================================================================


class TestWriteUpdatedSpec:
    def test_write_and_read_back(self):
        from prompt_hardener.agent_spec import write_updated_spec
        import yaml

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            output_path = f.name

        try:
            write_updated_spec(
                os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"),
                "Brand new system prompt.",
                output_path,
            )
            with open(output_path, "r") as f:
                data = yaml.safe_load(f)
            assert data["system_prompt"] == "Brand new system prompt."
            assert data["version"] == "1.0"
            assert data["type"] == "chatbot"
            assert data["name"] == "Simple FAQ Bot"
        finally:
            os.unlink(output_path)

    def test_preserves_other_fields(self):
        from prompt_hardener.agent_spec import write_updated_spec
        import yaml

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            output_path = f.name

        try:
            write_updated_spec(
                os.path.join(FIXTURES_DIR, "agent_spec.yaml"),
                "Updated prompt",
                output_path,
            )
            with open(output_path, "r") as f:
                data = yaml.safe_load(f)
            assert data["system_prompt"] == "Updated prompt"
            assert data["type"] == "agent"
            assert len(data["tools"]) == 3
            assert "policies" in data
        finally:
            os.unlink(output_path)
