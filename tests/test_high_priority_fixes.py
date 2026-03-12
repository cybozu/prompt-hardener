"""Regression tests for HIGH-priority bug fixes (H1-H6)."""

import json
import os

import pytest

from prompt_hardener.analyze.report import Finding
from prompt_hardener.analyze.scoring import compute_scores
from prompt_hardener.analyze.engine import run_analyze
from prompt_hardener.diff import compute_diff
from prompt_hardener.simulate import SimulationReport, SimulationSummary
from prompt_hardener.utils import average_satisfaction, extract_json_block

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _make_finding(rule_id, severity, layer):
    return Finding(
        id="f-test",
        rule_id=rule_id,
        title="Test",
        severity=severity,
        layer=layer,
        description="test",
    )


# =========================================================================
# H1: Score inflation when layer filter is used in analyze
# =========================================================================


class TestH1ScoreInflation:
    """compute_scores must only score the requested layers, not all TYPE_LAYERS."""

    def test_layers_filter_limits_scored_layers(self):
        """When layers=["prompt"], tool/arch should not appear in scores."""
        findings = [_make_finding("PROMPT-001", "high", "prompt")]
        scores, overall, risk = compute_scores(findings, "agent", layers=["prompt"])

        assert "prompt" in scores
        assert "tool" not in scores
        assert "architecture" not in scores
        # Overall should equal prompt score, not be diluted
        assert overall == scores["prompt"]

    def test_layers_filter_two_layers(self):
        findings = [
            _make_finding("PROMPT-001", "high", "prompt"),
            _make_finding("TOOL-001", "high", "tool"),
        ]
        scores, overall, risk = compute_scores(
            findings, "agent", layers=["prompt", "tool"]
        )

        assert "prompt" in scores
        assert "tool" in scores
        assert "architecture" not in scores
        assert overall == round((scores["prompt"] + scores["tool"]) / 2, 1)

    def test_layers_none_uses_all_type_layers(self):
        """When layers=None, all TYPE_LAYERS for the agent type are scored."""
        findings = [_make_finding("PROMPT-001", "high", "prompt")]
        scores, overall, risk = compute_scores(findings, "agent", layers=None)

        assert "prompt" in scores
        assert "tool" in scores
        assert "architecture" in scores

    def test_run_analyze_with_layer_filter_no_inflation(self):
        """Integration: analyze with layers=["prompt"] on agent spec."""
        spec_path = os.path.join(FIXTURES_DIR, "agent_insecure_spec.yaml")
        report = run_analyze(spec_path, layers=["prompt"])

        assert "prompt" in report.summary.scores_by_layer
        assert "tool" not in report.summary.scores_by_layer
        assert "architecture" not in report.summary.scores_by_layer
        assert report.summary.overall_score == report.summary.scores_by_layer["prompt"]


# =========================================================================
# H2: Missing 'layers' key in remediation metadata
# =========================================================================


class TestH2RemediationMetadataLayers:
    """Remediation metadata must include 'layers' key for report rendering."""

    def test_remediation_report_fixture_has_layers(self):
        """Fixture already has 'layers'; verify the report renderer can use it."""
        fixture_path = os.path.join(FIXTURES_DIR, "remediate_result.json")
        with open(fixture_path, "r") as f:
            data = json.load(f)
        assert "layers" in data["metadata"]
        assert isinstance(data["metadata"]["layers"], list)
        assert len(data["metadata"]["layers"]) > 0

    def test_remediate_engine_includes_layers_in_metadata(self):
        """run_remediate must populate metadata['layers']."""
        from unittest.mock import patch
        from prompt_hardener.remediate.engine import run_remediate
        from prompt_hardener.analyze.report import (
            AnalyzeReport,
            AnalyzeMetadata,
            AnalyzeSummary,
        )
        from prompt_hardener.remediate.report import PromptRemediation

        spec_path = os.path.join(FIXTURES_DIR, "agent_spec.yaml")

        mock_analyze_report = AnalyzeReport(
            metadata=AnalyzeMetadata(
                tool_version="0.5.0",
                timestamp="2026-01-01T00:00:00Z",
                agent_name="Test",
                agent_type="agent",
                spec_digest="sha256:test",
                rules_version="1.0",
                rules_evaluated=0,
            ),
            summary=AnalyzeSummary(
                risk_level="low",
                overall_score=10.0,
                scores_by_layer={"prompt": 10.0},
                finding_counts={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total": 0,
                },
            ),
            findings=[],
            attack_paths=[],
            recommended_fixes=[],
        )

        mock_prompt_result = (
            PromptRemediation(
                changes="No changes",
                techniques_selected=[],
                techniques_applied=[],
                findings_addressed=[],
            ),
            "improved prompt",
        )

        with patch(
            "prompt_hardener.remediate.engine.run_analyze",
            return_value=mock_analyze_report,
        ):
            with patch(
                "prompt_hardener.remediate.engine.remediate_prompt",
                return_value=mock_prompt_result,
            ):
                report = run_remediate(
                    spec_path=spec_path,
                    eval_api_mode="openai",
                    eval_model="gpt-4o-mini",
                    layers=["prompt"],
                )

        assert "layers" in report.metadata
        assert report.metadata["layers"] == ["prompt"]


# =========================================================================
# H3: Zero scenarios should not return 'critical' risk
# =========================================================================


class TestH3ZeroScenarios:
    """SimulationReport with 0 scenarios must not claim risk_level='critical'."""

    def test_zero_scenarios_not_critical(self):
        report = SimulationReport(
            scenarios=[],
            summary=SimulationSummary(total=0, blocked=0, succeeded=0, block_rate=0.0),
        )
        top = report._build_top_summary()
        assert top["risk_level"] != "critical"
        assert top["risk_level"] == "not_evaluated"

    def test_zero_scenarios_has_informative_finding(self):
        report = SimulationReport(
            scenarios=[],
            summary=SimulationSummary(total=0, blocked=0, succeeded=0, block_rate=0.0),
        )
        top = report._build_top_summary()
        assert len(top["key_findings"]) > 0
        assert "No scenarios" in top["key_findings"][0]

    def test_nonzero_scenarios_still_work(self):
        """Ensure existing risk level logic is unchanged for non-zero totals."""
        report = SimulationReport(
            scenarios=[],
            summary=SimulationSummary(total=10, blocked=9, succeeded=1, block_rate=0.9),
        )
        top = report._build_top_summary()
        assert top["risk_level"] == "low"

    def test_all_failed_is_critical(self):
        report = SimulationReport(
            scenarios=[],
            summary=SimulationSummary(total=5, blocked=0, succeeded=5, block_rate=0.0),
        )
        top = report._build_top_summary()
        assert top["risk_level"] == "critical"


# =========================================================================
# H4: average_satisfaction crash on non-dict values
# =========================================================================


class TestH4AverageSatisfaction:
    """average_satisfaction must handle non-dict category values gracefully."""

    def test_non_dict_string_value_ignored(self):
        evaluation = {
            "security": {"sub1": {"satisfaction": 8}},
            "notes": "unexpected string value",
        }
        score = average_satisfaction(evaluation)
        assert score == 8.0

    def test_non_dict_list_value_ignored(self):
        evaluation = {
            "security": {"sub1": {"satisfaction": 6}},
            "tags": ["a", "b"],
        }
        score = average_satisfaction(evaluation)
        assert score == 6.0

    def test_non_dict_int_value_ignored(self):
        evaluation = {
            "security": {"sub1": {"satisfaction": 7}},
            "count": 42,
        }
        score = average_satisfaction(evaluation)
        assert score == 7.0

    def test_empty_evaluation(self):
        assert average_satisfaction({}) == 0.0

    def test_all_skipped_keys(self):
        evaluation = {"critique": "good", "recommendation": "none"}
        assert average_satisfaction(evaluation) == 0.0

    def test_mixed_valid_and_invalid(self):
        evaluation = {
            "security": {"a": {"satisfaction": 8}, "b": {"satisfaction": 6}},
            "critique": "text",
            "extra_notes": "some string",
        }
        assert average_satisfaction(evaluation) == 7.0

    def test_missing_satisfaction_key_in_sub(self):
        """Sub-dict without 'satisfaction' key should be skipped."""
        evaluation = {
            "security": {
                "a": {"satisfaction": 10},
                "b": {"description": "no score here"},
            },
        }
        assert average_satisfaction(evaluation) == 10.0


# =========================================================================
# H5: diff missing has_persistent_memory and scope
# =========================================================================


class TestH5DiffMissingFields:
    """compute_diff must detect changes in has_persistent_memory and scope."""

    def _base_spec(self, **overrides):
        spec = {
            "version": "1.0",
            "type": "agent",
            "name": "Bot",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        spec.update(overrides)
        return spec

    def test_has_persistent_memory_modified(self):
        before = self._base_spec(has_persistent_memory="true")
        after = self._base_spec(has_persistent_memory="false")
        diff = compute_diff(before, after)
        paths = [c.path for c in diff.changes]
        assert "has_persistent_memory" in paths
        change = [c for c in diff.changes if c.path == "has_persistent_memory"][0]
        assert change.change_type == "modified"
        assert change.before == "true"
        assert change.after == "false"

    def test_scope_modified(self):
        before = self._base_spec(scope="single_user")
        after = self._base_spec(scope="multi_tenant")
        diff = compute_diff(before, after)
        paths = [c.path for c in diff.changes]
        assert "scope" in paths
        change = [c for c in diff.changes if c.path == "scope"][0]
        assert change.change_type == "modified"

    def test_has_persistent_memory_added(self):
        before = self._base_spec()
        after = self._base_spec(has_persistent_memory="true")
        diff = compute_diff(before, after)
        paths = [c.path for c in diff.changes]
        assert "has_persistent_memory" in paths
        change = [c for c in diff.changes if c.path == "has_persistent_memory"][0]
        assert change.change_type == "added"

    def test_scope_removed(self):
        before = self._base_spec(scope="shared_workspace")
        after = self._base_spec()
        diff = compute_diff(before, after)
        paths = [c.path for c in diff.changes]
        assert "scope" in paths
        change = [c for c in diff.changes if c.path == "scope"][0]
        assert change.change_type == "removed"

    def test_no_change_when_same(self):
        spec = self._base_spec(has_persistent_memory="true", scope="single_user")
        diff = compute_diff(spec, spec)
        assert len(diff.changes) == 0


# =========================================================================
# H6: extract_json_block greedy regex
# =========================================================================


class TestH6ExtractJsonBlock:
    """extract_json_block must find valid JSON even with multiple brace groups."""

    def test_valid_json_among_braces(self):
        text = 'Result: {"score": 5}. See {ref} for more.'
        result = extract_json_block(text)
        assert result == {"score": 5}

    def test_valid_json_after_invalid_braces(self):
        text = 'Some {invalid} then {"valid": true}'
        result = extract_json_block(text)
        assert result == {"valid": True}

    def test_nested_json_still_works(self):
        """Nested objects should still be extracted correctly."""
        text = '{"outer": {"inner": 1}}'
        result = extract_json_block(text)
        assert result == {"outer": {"inner": 1}}

    def test_markdown_wrapped_json(self):
        text = '```json\n{"key": "value"}\n```'
        result = extract_json_block(text)
        assert result == {"key": "value"}

    def test_json_with_surrounding_text(self):
        text = 'Here is the answer: {"a": 1, "b": 2}. Hope that helps!'
        result = extract_json_block(text)
        assert result == {"a": 1, "b": 2}

    def test_no_valid_json_raises(self):
        with pytest.raises(ValueError):
            extract_json_block("no json here at all")

    def test_existing_behavior_preserved(self):
        """Verify the original test cases still pass."""
        text = '{"prompt": "You are a helpful assistant."}'
        result = extract_json_block(text)
        assert result == {"prompt": "You are a helpful assistant."}
