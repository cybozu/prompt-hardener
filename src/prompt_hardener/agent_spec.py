"""YAML loader, JSON Schema validation, semantic validation, and AgentSpec conversion."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jsonschema
import yaml

from prompt_hardener.models import (
    AgentSpec,
    DataSource,
    EscalationRule,
    McpServer,
    Policies,
    ProviderConfig,
    ToolDef,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class ValidationMessage:
    """A single validation error or warning."""

    def __init__(self, level, path, message):
        # type: (str, str, str) -> None
        self.level = level   # "error" or "warning"
        self.path = path     # JSON-pointer-like path e.g. "(root)", "tools[0].name"
        self.message = message

    def __str__(self):
        # type: () -> str
        return "[%s] at '%s': %s" % (self.level.upper(), self.path, self.message)

    def __repr__(self):
        # type: () -> str
        return "ValidationMessage(%r, %r, %r)" % (self.level, self.path, self.message)


class ValidationResult:
    """Aggregated validation result."""

    def __init__(self):
        # type: () -> None
        self.errors = []   # type: List[ValidationMessage]
        self.warnings = []  # type: List[ValidationMessage]

    @property
    def is_valid(self):
        # type: () -> bool
        return len(self.errors) == 0

    def add_error(self, path, message):
        # type: (str, str) -> None
        self.errors.append(ValidationMessage("error", path, message))

    def add_warning(self, path, message):
        # type: (str, str) -> None
        self.warnings.append(ValidationMessage("warning", path, message))


# ---------------------------------------------------------------------------
# Schema path resolution
# ---------------------------------------------------------------------------

def _get_schema_path():
    # type: () -> Path
    return Path(__file__).parent / "schemas" / "agent_spec.schema.json"


def _load_schema():
    # type: () -> Dict[str, Any]
    schema_path = _get_schema_path()
    with open(str(schema_path), "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

def load_yaml(path):
    # type: (str) -> Dict[str, Any]
    """Load a YAML file and return the parsed dict.

    Raises ValueError on file-not-found or YAML syntax errors.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError("File not found: %s" % path)
    try:
        with open(str(file_path), "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError("YAML parse error in %s: %s" % (path, e))
    if not isinstance(data, dict):
        raise ValueError("Expected a YAML mapping at top level in %s" % path)
    return data


# ---------------------------------------------------------------------------
# JSON Schema validation
# ---------------------------------------------------------------------------

def validate_schema(data, result=None):
    # type: (Dict[str, Any], Optional[ValidationResult]) -> ValidationResult
    """Validate *data* against the agent_spec JSON Schema.

    Populates *result* (or creates a new one) with errors.
    """
    if result is None:
        result = ValidationResult()
    schema = _load_schema()

    validator_cls = jsonschema.Draft202012Validator
    validator = validator_cls(schema)

    for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        result.add_error(path, error.message)

    return result


# ---------------------------------------------------------------------------
# Semantic validation (cross-field consistency)
# ---------------------------------------------------------------------------

# Type-specific required fields for clearer error messages than jsonschema allOf
_TYPE_REQUIRED = {
    "rag": ["data_sources"],
    "agent": ["tools"],
    "mcp-agent": ["tools", "mcp_servers"],
}

# Fields that are irrelevant per type — presence yields a warning
_TYPE_IGNORED = {
    "chatbot": ["tools", "data_sources", "mcp_servers"],
    "rag": ["mcp_servers"],
    "agent": ["mcp_servers"],
}


def validate_semantic(data, result=None):
    # type: (Dict[str, Any], Optional[ValidationResult]) -> ValidationResult
    """Run semantic (cross-field) checks on *data*.

    Adds warnings (and sometimes errors) to *result*.
    """
    if result is None:
        result = ValidationResult()

    agent_type = data.get("type")

    # --- type-specific required fields (supplement jsonschema allOf) ---
    required = _TYPE_REQUIRED.get(agent_type, [])
    for field_name in required:
        if field_name not in data or not data[field_name]:
            result.add_error(
                field_name,
                "type '%s' requires '%s' field" % (agent_type, field_name),
            )

    # --- irrelevant field warnings ---
    ignored = _TYPE_IGNORED.get(agent_type, [])
    for field_name in ignored:
        if field_name in data and data[field_name]:
            result.add_warning(
                field_name,
                "'%s' is not used for type '%s' and will be ignored" % (field_name, agent_type),
            )

    # --- policies cross-checks ---
    tool_names = set()
    for t in data.get("tools") or []:
        if isinstance(t, dict):
            tool_names.add(t.get("name", ""))

    policies = data.get("policies") or {}
    for action in policies.get("allowed_actions") or []:
        if action not in tool_names and tool_names:
            result.add_warning(
                "policies.allowed_actions",
                "'%s' is listed in allowed_actions but not defined in tools" % action,
            )

    for action in policies.get("denied_actions") or []:
        if action in tool_names:
            result.add_warning(
                "policies.denied_actions",
                "'%s' is listed in denied_actions but is also defined in tools" % action,
            )

    # --- recommended field warnings ---
    if "user_input_description" not in data or not data.get("user_input_description"):
        result.add_warning(
            "user_input_description",
            "Missing 'user_input_description'. Analysis accuracy may be reduced.",
        )

    return result


# ---------------------------------------------------------------------------
# High-level validate
# ---------------------------------------------------------------------------

def validate(data):
    # type: (Dict[str, Any]) -> ValidationResult
    """Run both schema and semantic validation on *data*."""
    result = ValidationResult()
    validate_schema(data, result)
    validate_semantic(data, result)
    return result


# ---------------------------------------------------------------------------
# dict → AgentSpec conversion
# ---------------------------------------------------------------------------

def dict_to_agent_spec(data):
    # type: (Dict[str, Any]) -> AgentSpec
    """Convert a validated dict to an AgentSpec dataclass."""
    provider_data = data["provider"]
    provider = ProviderConfig(
        api=provider_data["api"],
        model=provider_data["model"],
        region=provider_data.get("region"),
        profile=provider_data.get("profile"),
    )

    tools = None
    if data.get("tools"):
        tools = [
            ToolDef(
                name=t["name"],
                description=t["description"],
                parameters=t.get("parameters"),
            )
            for t in data["tools"]
        ]

    policies = None
    if data.get("policies"):
        p = data["policies"]
        escalation_rules = None
        if p.get("escalation_rules"):
            escalation_rules = [
                EscalationRule(condition=r["condition"], action=r["action"])
                for r in p["escalation_rules"]
            ]
        policies = Policies(
            allowed_actions=p.get("allowed_actions"),
            denied_actions=p.get("denied_actions"),
            data_boundaries=p.get("data_boundaries"),
            escalation_rules=escalation_rules,
        )

    data_sources = None
    if data.get("data_sources"):
        data_sources = [
            DataSource(
                name=ds["name"],
                type=ds["type"],
                trust_level=ds["trust_level"],
                description=ds.get("description"),
            )
            for ds in data["data_sources"]
        ]

    mcp_servers = None
    if data.get("mcp_servers"):
        mcp_servers = [
            McpServer(
                name=ms["name"],
                trust_level=ms["trust_level"],
                allowed_tools=ms.get("allowed_tools"),
                data_access=ms.get("data_access"),
            )
            for ms in data["mcp_servers"]
        ]

    return AgentSpec(
        version=data["version"],
        type=data["type"],
        name=data["name"],
        system_prompt=data["system_prompt"],
        provider=provider,
        description=data.get("description"),
        messages=data.get("messages"),
        tools=tools,
        policies=policies,
        data_sources=data_sources,
        mcp_servers=mcp_servers,
        user_input_description=data.get("user_input_description"),
    )


# ---------------------------------------------------------------------------
# All-in-one: load + validate + convert
# ---------------------------------------------------------------------------

def load_and_validate(path):
    # type: (str) -> Tuple[AgentSpec, ValidationResult]
    """Load a YAML file, validate it, and return (AgentSpec, ValidationResult).

    Raises ValueError if the file cannot be loaded or parsed.
    If validation errors exist, AgentSpec conversion is still attempted
    for best-effort usage, but callers should check result.is_valid.
    """
    data = load_yaml(path)
    result = validate(data)
    spec = dict_to_agent_spec(data) if result.is_valid else None
    return spec, result
