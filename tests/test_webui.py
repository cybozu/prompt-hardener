"""Tests for the webui module backend functions."""

import json
import os
import tempfile

import yaml

from prompt_hardener.webui import (
    download_yaml,
    load_template,
    run_diff_webui,
    run_report_webui,
    upload_yaml,
    validate_yaml_text,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
TEMPLATES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "src", "prompt_hardener", "templates"
)


def _write_temp_yaml(data):
    """Write a dict as YAML to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(
        suffix=".yaml", mode="w", delete=False, encoding="utf-8"
    )
    yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
    f.close()
    return f.name


# =========================================================================
# load_template
# =========================================================================


class TestLoadTemplate:
    def test_load_chatbot_template(self):
        result = load_template("chatbot")
        assert (
            "type: chatbot" in result
            or "type: 'chatbot'" in result
            or 'type: "chatbot"' in result
        )

    def test_load_rag_template(self):
        result = load_template("rag")
        assert "type:" in result
        assert "rag" in result

    def test_load_agent_template(self):
        result = load_template("agent")
        assert "type:" in result

    def test_load_mcp_agent_template(self):
        result = load_template("mcp-agent")
        assert "type:" in result

    def test_load_all_templates_are_valid_yaml(self):
        for agent_type in ["chatbot", "rag", "agent", "mcp-agent"]:
            content = load_template(agent_type)
            data = yaml.safe_load(content)
            assert isinstance(data, dict), (
                "Template %s should parse to a dict" % agent_type
            )
            assert "type" in data
            assert "version" in data

    def test_load_nonexistent_template(self):
        result = load_template("nonexistent")
        assert "Error" in result


# =========================================================================
# upload_yaml
# =========================================================================


class TestUploadYaml:
    def test_upload_yaml_file(self):
        data = {"version": "1.0", "type": "chatbot", "name": "Test"}
        path = _write_temp_yaml(data)
        try:
            result = upload_yaml(path)
            assert "version" in result
            assert "chatbot" in result
        finally:
            os.unlink(path)

    def test_upload_none(self):
        result = upload_yaml(None)
        assert result == ""


# =========================================================================
# validate_yaml_text
# =========================================================================


class TestValidateYamlText:
    def test_valid_chatbot_spec(self):
        yaml_text = load_template("chatbot")
        result = validate_yaml_text(yaml_text)
        # Should not have errors (might have warnings about user_input_description)
        assert "Error" not in result or "Validation passed" in result

    def test_empty_input(self):
        result = validate_yaml_text("")
        assert "No YAML content" in result

    def test_none_input(self):
        result = validate_yaml_text(None)
        assert "No YAML content" in result

    def test_invalid_yaml_syntax(self):
        result = validate_yaml_text("{ bad yaml: [")
        assert "Parse Error" in result or "Error" in result

    def test_non_mapping_yaml(self):
        result = validate_yaml_text("- item1\n- item2")
        assert "mapping" in result.lower() or "Error" in result

    def test_valid_spec_with_all_fields(self):
        yaml_text = """
version: "1.0"
type: chatbot
name: "Test Bot"
system_prompt: "You are helpful."
provider:
  api: openai
  model: gpt-4o
user_input_description: "Free-form text"
"""
        result = validate_yaml_text(yaml_text)
        assert "passed" in result.lower()


# =========================================================================
# download_yaml
# =========================================================================


class TestDownloadYaml:
    def test_download_returns_file_path(self):
        yaml_text = "version: '1.0'\ntype: chatbot\n"
        path = download_yaml(yaml_text)
        assert path is not None
        assert path.endswith(".yaml")
        content = open(path, "r", encoding="utf-8").read()
        assert content == yaml_text
        os.unlink(path)

    def test_download_empty_returns_none(self):
        assert download_yaml("") is None
        assert download_yaml(None) is None
        assert download_yaml("   ") is None


# =========================================================================
# run_report_webui
# =========================================================================


class TestRunReportWebui:
    def test_generate_markdown_from_analyze_result(self):
        fixture_path = os.path.join(FIXTURES_DIR, "analyze_result.json")
        status, preview, download = run_report_webui(fixture_path, "markdown")
        assert "Report Generated" in status
        assert "Analysis Report" in preview
        assert download is not None
        assert download.endswith(".md")
        os.unlink(download)

    def test_generate_html_from_analyze_result(self):
        fixture_path = os.path.join(FIXTURES_DIR, "analyze_result.json")
        status, preview, download = run_report_webui(fixture_path, "html")
        assert "Report Generated" in status
        assert preview == ""  # HTML format doesn't show markdown preview
        assert download is not None
        assert download.endswith(".html")
        os.unlink(download)

    def test_generate_json_from_analyze_result(self):
        fixture_path = os.path.join(FIXTURES_DIR, "analyze_result.json")
        status, preview, download = run_report_webui(fixture_path, "json")
        assert "Report Generated" in status
        assert download is not None
        assert download.endswith(".json")
        os.unlink(download)

    def test_no_file_uploaded(self):
        status, preview, download = run_report_webui(None, "markdown")
        assert "Error" in status
        assert download is None

    def test_simulate_result(self):
        fixture_path = os.path.join(FIXTURES_DIR, "simulate_result.json")
        if os.path.exists(fixture_path):
            status, preview, download = run_report_webui(fixture_path, "markdown")
            assert "Report Generated" in status
            if download:
                os.unlink(download)

    def test_remediate_result(self):
        fixture_path = os.path.join(FIXTURES_DIR, "remediate_result.json")
        if os.path.exists(fixture_path):
            status, preview, download = run_report_webui(fixture_path, "markdown")
            assert "Report Generated" in status
            if download:
                os.unlink(download)


# =========================================================================
# run_diff_webui
# =========================================================================


class TestRunDiffWebui:
    def test_diff_identical_files(self):
        spec = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are helpful.",
            "provider": {"api": "openai", "model": "gpt-4o"},
        }
        path1 = _write_temp_yaml(spec)
        path2 = _write_temp_yaml(spec)
        try:
            status, md = run_diff_webui(path1, path2)
            assert "Diff Complete" in status
            assert "No differences" in md
        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_diff_different_files(self):
        spec1 = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "You are helpful.",
            "provider": {"api": "openai", "model": "gpt-4o"},
        }
        spec2 = {
            "version": "1.0",
            "type": "agent",
            "name": "Agent",
            "system_prompt": "You are an agent.",
            "tools": [{"name": "search", "description": "Search the web"}],
            "provider": {"api": "openai", "model": "gpt-4o"},
        }
        path1 = _write_temp_yaml(spec1)
        path2 = _write_temp_yaml(spec2)
        try:
            status, md = run_diff_webui(path1, path2)
            assert "Diff Complete" in status
            assert "Changes" in md
        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_diff_missing_before(self):
        spec = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "Hi",
            "provider": {"api": "openai", "model": "m"},
        }
        path = _write_temp_yaml(spec)
        try:
            status, md = run_diff_webui(None, path)
            assert "Error" in status
        finally:
            os.unlink(path)

    def test_diff_missing_after(self):
        spec = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Bot",
            "system_prompt": "Hi",
            "provider": {"api": "openai", "model": "m"},
        }
        path = _write_temp_yaml(spec)
        try:
            status, md = run_diff_webui(path, None)
            assert "Error" in status
        finally:
            os.unlink(path)


# =========================================================================
# run_analyze_webui (mocked)
# =========================================================================


class TestRunAnalyzeWebui:
    def test_no_spec_file(self):
        from prompt_hardener.webui import run_analyze_webui

        status, md, json_dl, html_dl = run_analyze_webui(None, [])
        assert "Error" in status
        assert json_dl is None
        assert html_dl is None

    def test_analyze_with_mock(self, monkeypatch):
        from prompt_hardener.webui import run_analyze_webui

        # Create a minimal spec file
        spec = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Test",
            "system_prompt": "You are helpful.",
            "provider": {"api": "openai", "model": "gpt-4o"},
        }
        spec_path = _write_temp_yaml(spec)

        # Mock run_analyze to return a fixture-like result
        class MockReport:
            def to_dict(self):
                with open(os.path.join(FIXTURES_DIR, "analyze_result.json")) as f:
                    return json.load(f)

        monkeypatch.setattr(
            "prompt_hardener.analyze.engine.run_analyze",
            lambda *args, **kwargs: MockReport(),
        )

        try:
            status, md, json_dl, html_dl = run_analyze_webui(spec_path, [])
            assert "Analysis Complete" in status
            assert "Analysis Report" in md
            assert json_dl is not None
            assert html_dl is not None
            if json_dl:
                os.unlink(json_dl)
            if html_dl:
                os.unlink(html_dl)
        finally:
            os.unlink(spec_path)


# =========================================================================
# run_simulate_webui (mocked)
# =========================================================================


class TestRunSimulateWebui:
    def test_no_spec_file(self):
        from prompt_hardener.webui import run_simulate_webui

        status, md, json_dl, html_dl = run_simulate_webui(
            None, "openai", "gpt-4o", "openai", "gpt-4o", [], [], None, None, None
        )
        assert "Error" in status

    def test_missing_api_settings(self):
        from prompt_hardener.webui import run_simulate_webui

        spec = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Test",
            "system_prompt": "Hi",
            "provider": {"api": "openai", "model": "m"},
        }
        path = _write_temp_yaml(spec)
        try:
            status, md, json_dl, html_dl = run_simulate_webui(
                path, None, None, None, None, [], [], None, None, None
            )
            assert "Error" in status
        finally:
            os.unlink(path)


# =========================================================================
# run_remediate_webui (mocked)
# =========================================================================


class TestRunRemediateWebui:
    def test_no_spec_file(self):
        from prompt_hardener.webui import run_remediate_webui

        status, md, json_dl, html_dl, spec_dl = run_remediate_webui(
            None, [], "openai", "gpt-4o", 3, 8.5, [], None, None
        )
        assert "Error" in status

    def test_missing_eval_settings(self):
        from prompt_hardener.webui import run_remediate_webui

        spec = {
            "version": "1.0",
            "type": "chatbot",
            "name": "Test",
            "system_prompt": "Hi",
            "provider": {"api": "openai", "model": "m"},
        }
        path = _write_temp_yaml(spec)
        try:
            status, md, json_dl, html_dl, spec_dl = run_remediate_webui(
                path, [], None, None, 3, 8.5, [], None, None
            )
            assert "Error" in status
        finally:
            os.unlink(path)
