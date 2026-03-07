"""Tests for agent_spec loading, validation, data model, CLI, and roundtrip."""

import json
import os
import subprocess
import sys
import tempfile

import pytest
import yaml

from prompt_hardener.agent_spec import (
    ValidationResult,
    dict_to_agent_spec,
    load_and_validate,
    load_yaml,
    validate,
    validate_schema,
    validate_semantic,
)
from prompt_hardener.models import (
    AgentSpec,
    DataSource,
    McpServer,
    Policies,
    ProviderConfig,
    ToolDef,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
INVALID_DIR = os.path.join(FIXTURES_DIR, "invalid")
EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")


# =========================================================================
# Group 1: YAML Loading
# =========================================================================


class TestYamlLoading:
    @pytest.mark.parametrize(
        "filename",
        [
            "chatbot_spec.yaml",
            "rag_spec.yaml",
            "agent_spec.yaml",
            "mcp_agent_spec.yaml",
        ],
    )
    def test_load_valid_fixture(self, filename):
        path = os.path.join(FIXTURES_DIR, filename)
        data = load_yaml(path)
        assert isinstance(data, dict)
        assert "version" in data
        assert "type" in data

    def test_load_nonexistent_file(self):
        with pytest.raises(ValueError, match="File not found"):
            load_yaml("/nonexistent/path.yaml")

    def test_load_invalid_yaml_syntax(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(":\n  bad: [yaml\n  unclosed")
            f.flush()
            path = f.name
        try:
            with pytest.raises(ValueError, match="YAML parse error"):
                load_yaml(path)
        finally:
            os.unlink(path)


# =========================================================================
# Group 2: Schema Validation — Valid
# =========================================================================


class TestSchemaValidationValid:
    @pytest.mark.parametrize(
        "filename",
        [
            "chatbot_spec.yaml",
            "rag_spec.yaml",
            "agent_spec.yaml",
            "mcp_agent_spec.yaml",
        ],
    )
    def test_valid_fixture(self, filename):
        path = os.path.join(FIXTURES_DIR, filename)
        data = load_yaml(path)
        result = validate_schema(data)
        assert result.is_valid, [str(e) for e in result.errors]


# =========================================================================
# Group 3: Schema Validation — Invalid
# =========================================================================


class TestSchemaValidationInvalid:
    def test_missing_version(self):
        data = load_yaml(os.path.join(INVALID_DIR, "missing_version.yaml"))
        result = validate_schema(data)
        assert not result.is_valid
        assert any("version" in str(e) for e in result.errors)

    def test_wrong_version(self):
        data = load_yaml(os.path.join(INVALID_DIR, "wrong_version.yaml"))
        result = validate_schema(data)
        assert not result.is_valid

    def test_missing_system_prompt(self):
        data = load_yaml(os.path.join(INVALID_DIR, "missing_system_prompt.yaml"))
        result = validate_schema(data)
        assert not result.is_valid
        assert any("system_prompt" in str(e) for e in result.errors)

    def test_invalid_type(self):
        data = load_yaml(os.path.join(INVALID_DIR, "invalid_type.yaml"))
        result = validate_schema(data)
        assert not result.is_valid

    def test_rag_no_data_sources(self):
        data = load_yaml(os.path.join(INVALID_DIR, "rag_no_data_sources.yaml"))
        result = validate(data)
        assert not result.is_valid
        assert any("data_sources" in str(e) for e in result.errors)

    def test_agent_no_tools(self):
        data = load_yaml(os.path.join(INVALID_DIR, "agent_no_tools.yaml"))
        result = validate(data)
        assert not result.is_valid
        assert any("tools" in str(e) for e in result.errors)

    def test_mcp_no_servers(self):
        data = load_yaml(os.path.join(INVALID_DIR, "mcp_no_servers.yaml"))
        result = validate(data)
        assert not result.is_valid
        assert any("mcp_servers" in str(e) for e in result.errors)

    def test_extra_field(self):
        data = load_yaml(os.path.join(INVALID_DIR, "extra_field.yaml"))
        result = validate_schema(data)
        assert not result.is_valid
        assert any("additional" in str(e).lower() or "unknown_field" in str(e) for e in result.errors)


# =========================================================================
# Group 4: Semantic Validation
# =========================================================================


class TestSemanticValidation:
    def test_allowed_actions_unknown_tool(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "agent_spec.yaml"))
        data["policies"]["allowed_actions"].append("nonexistent_tool")
        result = validate_semantic(data)
        assert any(
            "nonexistent_tool" in str(w) and "allowed_actions" in str(w)
            for w in result.warnings
        )

    def test_denied_actions_defined_tool(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "agent_spec.yaml"))
        data["policies"]["denied_actions"].append("get_order_status")
        result = validate_semantic(data)
        assert any(
            "get_order_status" in str(w) and "denied_actions" in str(w)
            for w in result.warnings
        )

    def test_chatbot_with_tools_warning(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"))
        data["tools"] = [{"name": "test", "description": "test tool"}]
        result = validate_semantic(data)
        assert any(
            "tools" in str(w) and "ignored" in str(w).lower()
            for w in result.warnings
        )

    def test_missing_user_input_description(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"))
        del data["user_input_description"]
        result = validate_semantic(data)
        assert any("user_input_description" in str(w) for w in result.warnings)


# =========================================================================
# Group 5: Data Model Conversion
# =========================================================================


class TestDataModelConversion:
    def test_chatbot_dict_to_agent_spec(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"))
        spec = dict_to_agent_spec(data)
        assert isinstance(spec, AgentSpec)
        assert spec.version == "1.0"
        assert spec.type == "chatbot"
        assert spec.name == "Simple FAQ Bot"
        assert spec.provider.api == "openai"
        assert spec.provider.model == "gpt-4o-mini"
        assert spec.tools is None
        assert spec.mcp_servers is None

    def test_agent_dict_to_agent_spec_tools(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "agent_spec.yaml"))
        spec = dict_to_agent_spec(data)
        assert spec.tools is not None
        assert len(spec.tools) == 3
        assert isinstance(spec.tools[0], ToolDef)
        assert spec.tools[0].name == "get_order_status"

    def test_openai_to_prompt_input(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "chatbot_spec.yaml"))
        spec = dict_to_agent_spec(data)
        pi = spec.to_prompt_input()
        assert pi.mode == "chat"
        assert pi.messages_format == "openai"
        # OpenAI format: system_prompt becomes first message
        assert pi.messages[0]["role"] == "system"
        assert "FAQ" in pi.messages[0]["content"]

    def test_claude_to_prompt_input(self):
        data = load_yaml(os.path.join(FIXTURES_DIR, "rag_spec.yaml"))
        spec = dict_to_agent_spec(data)
        pi = spec.to_prompt_input()
        assert pi.mode == "chat"
        assert pi.messages_format == "claude"
        assert pi.system_prompt is not None
        assert "document" in pi.system_prompt.lower()


# =========================================================================
# Group 6: CLI Integration
# =========================================================================


class TestCLIIntegration:
    def test_init_chatbot(self, tmp_path):
        output = tmp_path / "agent_spec.yaml"
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "init", "--type", "chatbot", "-o", str(output),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert output.exists()
        assert "Created" in result.stdout

    def test_init_no_overwrite(self, tmp_path):
        output = tmp_path / "agent_spec.yaml"
        output.write_text("existing content")
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "init", "--type", "chatbot", "-o", str(output),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "already exists" in result.stdout

    def test_validate_valid_spec(self):
        spec_path = os.path.join(FIXTURES_DIR, "chatbot_spec.yaml")
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "validate", spec_path,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "is valid" in result.stdout

    def test_validate_invalid_spec(self):
        spec_path = os.path.join(INVALID_DIR, "missing_version.yaml")
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "validate", spec_path,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "error" in result.stdout.lower()


# =========================================================================
# Group 7: Roundtrip — init → validate
# =========================================================================


class TestRoundtrip:
    def test_init_validate_chatbot(self, tmp_path):
        output = tmp_path / "spec.yaml"
        subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "init", "--type", "chatbot", "-o", str(output),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "validate", str(output),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout

    @pytest.mark.parametrize("agent_type", ["chatbot", "rag", "agent", "mcp-agent"])
    def test_init_validate_all_types(self, tmp_path, agent_type):
        output = tmp_path / ("spec_%s.yaml" % agent_type.replace("-", "_"))
        subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "init", "--type", agent_type, "-o", str(output),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        result = subprocess.run(
            [
                sys.executable, "-m", "prompt_hardener.main",
                "validate", str(output),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            "validate failed for type %s: %s" % (agent_type, result.stdout)
        )


# =========================================================================
# Group 8: Examples Validation
# =========================================================================


class TestExamplesValidation:
    @pytest.mark.parametrize(
        "example_dir",
        ["chatbot-minimal", "rag-internal-assistant", "agent-basic"],
    )
    def test_example_validates(self, example_dir):
        spec_path = os.path.join(EXAMPLES_DIR, example_dir, "agent_spec.yaml")
        data = load_yaml(spec_path)
        result = validate(data)
        assert result.is_valid, [str(e) for e in result.errors]


# =========================================================================
# Group 9: Schema Drift Guard
# =========================================================================


class TestSchemaDriftGuard:
    def test_agent_spec_fields_match_schema(self):
        """Verify AgentSpec dataclass fields correspond to JSON Schema properties."""
        schema_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "src",
            "prompt_hardener",
            "schemas",
            "agent_spec.schema.json",
        )
        with open(schema_path, "r") as f:
            schema = json.load(f)

        schema_props = set(schema["properties"].keys())

        # AgentSpec field names (matching schema keys)
        import dataclasses

        spec_fields = set(f.name for f in dataclasses.fields(AgentSpec))

        # All schema properties should have a corresponding dataclass field
        for prop in schema_props:
            assert prop in spec_fields, (
                "Schema property '%s' has no corresponding AgentSpec field" % prop
            )

        # All dataclass fields should have a corresponding schema property
        for field_name in spec_fields:
            assert field_name in schema_props, (
                "AgentSpec field '%s' has no corresponding schema property" % field_name
            )
