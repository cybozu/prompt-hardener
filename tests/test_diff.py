"""Tests for the diff module."""

import json
import os
import tempfile

import pytest
import yaml

from prompt_hardener.diff import (
    FieldDiff,
    SpecDiff,
    compute_diff,
    render_json_diff,
    render_markdown_diff,
    render_text_diff,
    run_diff,
)

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


def _write_temp_yaml(data):
    """Write a dict as YAML to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False, encoding="utf-8")
    yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    f.close()
    return f.name


# =========================================================================
# compute_diff
# =========================================================================

class TestComputeDiff:
    def test_identical_specs(self):
        spec = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        diff = compute_diff(spec, spec)
        assert len(diff.changes) == 0
        assert diff.system_prompt_diff is None

    def test_scalar_field_modified(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot A",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["name"] = "Bot B"
        diff = compute_diff(before, after)
        name_changes = [c for c in diff.changes if c.path == "name"]
        assert len(name_changes) == 1
        assert name_changes[0].change_type == "modified"
        assert name_changes[0].before == "Bot A"
        assert name_changes[0].after == "Bot B"

    def test_scalar_field_added(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["description"] = "A helpful bot"
        diff = compute_diff(before, after)
        desc_changes = [c for c in diff.changes if c.path == "description"]
        assert len(desc_changes) == 1
        assert desc_changes[0].change_type == "added"
        assert desc_changes[0].after == "A helpful bot"

    def test_scalar_field_removed(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "description": "A bot",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["description"] = None
        diff = compute_diff(before, after)
        desc_changes = [c for c in diff.changes if c.path == "description"]
        assert len(desc_changes) == 1
        assert desc_changes[0].change_type == "removed"

    def test_type_change(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["type"] = "agent"
        diff = compute_diff(before, after)
        assert diff.before_type == "chatbot"
        assert diff.after_type == "agent"
        type_changes = [c for c in diff.changes if c.path == "type"]
        assert len(type_changes) == 1
        assert type_changes[0].change_type == "modified"

    def test_tools_added(self):
        before = {
            "version": "1.0",
            "type": "agent",
            "name": "Agent",
            "system_prompt": "You are an agent.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["tools"] = [{"name": "search", "description": "Search docs"}]
        diff = compute_diff(before, after)
        tool_changes = [c for c in diff.changes if c.path.startswith("tools")]
        assert len(tool_changes) == 1
        assert tool_changes[0].change_type == "added"
        assert "search" in tool_changes[0].path

    def test_tools_removed(self):
        before = {
            "version": "1.0",
            "type": "agent",
            "name": "Agent",
            "system_prompt": "You are an agent.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
            "tools": [{"name": "search", "description": "Search docs"}],
        }
        after = dict(before)
        after["tools"] = []
        diff = compute_diff(before, after)
        tool_changes = [c for c in diff.changes if c.path.startswith("tools")]
        assert len(tool_changes) == 1
        assert tool_changes[0].change_type == "removed"

    def test_tools_modified(self):
        before = {
            "version": "1.0",
            "type": "agent",
            "name": "Agent",
            "system_prompt": "You are an agent.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
            "tools": [{"name": "search", "description": "Old desc"}],
        }
        after = dict(before)
        after["tools"] = [{"name": "search", "description": "New desc"}]
        diff = compute_diff(before, after)
        tool_changes = [c for c in diff.changes if c.path.startswith("tools")]
        assert len(tool_changes) == 1
        assert tool_changes[0].change_type == "modified"

    def test_policies_diff(self):
        before = {
            "version": "1.0",
            "type": "agent",
            "name": "Agent",
            "system_prompt": "You are an agent.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
            "policies": {
                "allowed_actions": ["search"],
                "denied_actions": ["delete"],
            },
        }
        after = dict(before)
        after["policies"] = {
            "allowed_actions": ["search", "create"],
            "denied_actions": ["delete"],
        }
        diff = compute_diff(before, after)
        pol_changes = [c for c in diff.changes if c.path.startswith("policies")]
        assert len(pol_changes) == 1
        assert pol_changes[0].path == "policies.allowed_actions"
        assert pol_changes[0].change_type == "modified"

    def test_provider_diff(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["provider"] = {"api": "claude", "model": "claude-3-7-sonnet"}
        diff = compute_diff(before, after)
        prov_changes = [c for c in diff.changes if c.path.startswith("provider")]
        assert len(prov_changes) == 2  # api and model
        paths = {c.path for c in prov_changes}
        assert "provider.api" in paths
        assert "provider.model" in paths


# =========================================================================
# System prompt diff
# =========================================================================

class TestSystemPromptDiff:
    def test_single_line_change(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are a bot.",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["system_prompt"] = "You are a helpful bot."
        diff = compute_diff(before, after)
        assert diff.system_prompt_diff is not None
        assert "---" in diff.system_prompt_diff
        assert "+++" in diff.system_prompt_diff

    def test_multiline_diff(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "Line 1\nLine 2\nLine 3\n",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after = dict(before)
        after["system_prompt"] = "Line 1\nModified Line 2\nLine 3\nLine 4\n"
        diff = compute_diff(before, after)
        assert diff.system_prompt_diff is not None
        assert "-Line 2" in diff.system_prompt_diff
        assert "+Modified Line 2" in diff.system_prompt_diff
        assert "+Line 4" in diff.system_prompt_diff

    def test_no_diff_when_same(self):
        before = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "Same prompt\n",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        diff = compute_diff(before, before)
        assert diff.system_prompt_diff is None


# =========================================================================
# Rendering
# =========================================================================

class TestDiffRendering:
    @pytest.fixture
    def sample_diff(self):
        return SpecDiff(
            before_path="before.yaml",
            after_path="after.yaml",
            before_type="chatbot",
            after_type="agent",
            changes=[
                FieldDiff(path="type", change_type="modified", before="chatbot", after="agent"),
                FieldDiff(path="name", change_type="modified", before="Old Bot", after="New Agent"),
                FieldDiff(path="system_prompt", change_type="modified",
                          before="You are a bot.", after="You are an agent."),
                FieldDiff(path="tools[search]", change_type="added",
                          after='{"name": "search", "description": "Search docs"}'),
            ],
            system_prompt_diff="--- before/system_prompt\n+++ after/system_prompt\n@@ -1 +1 @@\n-You are a bot.\n+You are an agent.\n",
        )

    def test_text_rendering(self, sample_diff):
        output = render_text_diff(sample_diff)
        assert "before.yaml" in output
        assert "after.yaml" in output
        assert "chatbot -> agent" in output
        assert "[modified]" in output
        assert "[added]" in output
        assert "system_prompt" in output

    def test_json_rendering(self, sample_diff):
        output = render_json_diff(sample_diff)
        parsed = json.loads(output)
        assert parsed["before_path"] == "before.yaml"
        assert parsed["after_path"] == "after.yaml"
        assert parsed["before_type"] == "chatbot"
        assert parsed["after_type"] == "agent"
        assert len(parsed["changes"]) == 4
        assert "system_prompt_diff" in parsed

    def test_markdown_rendering(self, sample_diff):
        output = render_markdown_diff(sample_diff)
        assert "# Agent Spec Diff" in output
        assert "before.yaml" in output
        assert "after.yaml" in output
        assert "```diff" in output
        assert "## Changes" in output
        assert "modified" in output
        assert "added" in output

    def test_no_changes(self):
        diff = SpecDiff(
            before_path="a.yaml",
            after_path="b.yaml",
            before_type="chatbot",
            after_type="chatbot",
        )
        text = render_text_diff(diff)
        assert "No differences found" in text

        md = render_markdown_diff(diff)
        assert "No differences found" in md

        json_out = render_json_diff(diff)
        parsed = json.loads(json_out)
        assert parsed["changes"] == []


# =========================================================================
# run_diff (integration)
# =========================================================================

class TestRunDiff:
    def test_diff_same_file(self):
        spec_path = os.path.join(EXAMPLES_DIR, "chatbot-minimal", "agent_spec.yaml")
        output = run_diff(spec_path, spec_path, "text")
        assert "No differences found" in output

    def test_diff_different_files_text(self):
        before = os.path.join(EXAMPLES_DIR, "chatbot-minimal", "agent_spec.yaml")
        after = os.path.join(EXAMPLES_DIR, "agent-basic", "agent_spec.yaml")
        output = run_diff(before, after, "text")
        assert "[modified]" in output
        # Type changed from chatbot to agent
        assert "type" in output

    def test_diff_different_files_json(self):
        before = os.path.join(EXAMPLES_DIR, "chatbot-minimal", "agent_spec.yaml")
        after = os.path.join(EXAMPLES_DIR, "agent-basic", "agent_spec.yaml")
        output = run_diff(before, after, "json")
        parsed = json.loads(output)
        assert parsed["before_type"] == "chatbot"
        assert parsed["after_type"] == "agent"
        assert len(parsed["changes"]) > 0

    def test_diff_different_files_markdown(self):
        before = os.path.join(EXAMPLES_DIR, "chatbot-minimal", "agent_spec.yaml")
        after = os.path.join(EXAMPLES_DIR, "agent-basic", "agent_spec.yaml")
        output = run_diff(before, after, "markdown")
        assert "# Agent Spec Diff" in output
        assert "```diff" in output

    def test_diff_temp_files(self):
        before_data = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are a bot.\nBe helpful.\n",
            "provider": {"api": "openai", "model": "gpt-4o-mini"},
        }
        after_data = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Improved Bot",
            "system_prompt": "You are a helpful bot.\nBe helpful.\nBe safe.\n",
            "provider": {"api": "openai", "model": "gpt-4o"},
        }
        before_path = _write_temp_yaml(before_data)
        after_path = _write_temp_yaml(after_data)
        try:
            output = run_diff(before_path, after_path, "text")
            assert "[modified]" in output
            assert "name" in output
            assert "system_prompt" in output
            assert "provider.model" in output
        finally:
            os.unlink(before_path)
            os.unlink(after_path)

    def test_invalid_format(self):
        spec_path = os.path.join(EXAMPLES_DIR, "chatbot-minimal", "agent_spec.yaml")
        with pytest.raises(ValueError, match="Unsupported diff format"):
            run_diff(spec_path, spec_path, "pdf")

    def test_nonexistent_file(self):
        with pytest.raises(ValueError, match="File not found"):
            run_diff("/nonexistent.yaml", "/also_nonexistent.yaml")
