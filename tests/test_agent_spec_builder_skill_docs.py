from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = PROJECT_ROOT / ".agents" / "skills" / "agent-spec-builder"


def _read(relative_path: str) -> str:
    return (SKILL_ROOT / relative_path).read_text(encoding="utf-8")


def test_field_catalog_tracks_current_rule_inventory():
    text = _read("references/field-catalog.md")

    current_rules = [
        "PROMPT-001",
        "PROMPT-002",
        "PROMPT-004",
        "TOOL-001",
        "TOOL-002",
        "TOOL-003",
        "TOOL-004",
        "TOOL-005",
        "TOOL-006",
        "TOOL-007",
        "TOOL-008",
        "ARCH-002",
        "ARCH-003",
        "ARCH-004",
        "ARCH-005",
        "ARCH-006",
        "ARCH-007",
        "ARCH-008",
        "ARCH-009",
    ]

    for rule_id in current_rules:
        assert rule_id in text

    for deprecated_rule in ["PROMPT-003", "ARCH-001"]:
        assert deprecated_rule not in text


def test_output_templates_cover_provenance_and_budget_fields():
    text = _read("references/output-templates.md")

    required_snippets = [
        "source: <local|third_party|mcp|unknown>",
        'content_hash: "sha256:..."',
        "source: <first_party|third_party|unknown>",
        "max_tool_calls",
        "max_steps",
        "rate_limits",
        "cost_budget",
        "ARCH-009",
        "tools[<N>].parameters.properties.<dangerous_param>",
    ]

    for snippet in required_snippets:
        assert snippet in text


def test_question_flow_collects_budget_provenance_and_isolation_inputs():
    text = _read("references/question-flow.md")

    required_snippets = [
        "execution identity",
        "content hash",
        "Policies And Budgets",
        "max tool calls",
        "Persistent Memory And Protections",
        "tenant or user isolation controls exist",
        "data_sources[]",
        "source` | Default to `unknown`",
    ]

    for snippet in required_snippets:
        assert snippet in text


def test_skill_is_self_contained_and_tracks_expanded_scan_targets():
    text = _read("SKILL.md")

    required_snippets = [
        "portable",
        "bundled files in `references/` as the primary source of truth",
        "optional cross-check",
        "Do not assume they exist.",
        "dangerous free-form parameters relevant to TOOL-007",
        "duplicate, confusing, or overly generic tool names relevant to TOOL-008",
        "policies.max_tool_calls",
        "memory poisoning protections relevant to ARCH-005",
        "tenant or user isolation relevant to ARCH-007",
    ]

    for snippet in required_snippets:
        assert snippet in text
