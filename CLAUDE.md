# Prompt Hardener

Automated evaluation and hardening of LLM system prompts against prompt injection attacks.

## Project Overview

Prompt Hardener is an open-source CLI tool that evaluates and strengthens system prompts used in LLM-based applications. It uses a **unified agent specification** (`agent_spec.yaml`) to describe the agent under test, then performs layered security analysis, iterative remediation, and attack simulation.

### Supported Agent Types

| Type | Description | Analyzed Layers |
|------|-------------|-----------------|
| `chatbot` | Simple conversational bots | prompt |
| `rag` | Retrieval-augmented generation systems | prompt, architecture |
| `agent` | Tool-calling agents | prompt, tool, architecture |
| `mcp-agent` | MCP server-connected agents | prompt, tool, architecture |

### Core Workflow

```
init -> validate -> analyze -> remediate -> simulate -> report -> diff
```

1. **init** - Generate an `agent_spec.yaml` from a template
2. **validate** - Schema + semantic validation of the spec
3. **analyze** - Static rule-based analysis + optional LLM evaluation
4. **remediate** - Three-layer remediation (prompt / tool / architecture)
5. **simulate** - Run attack scenarios from the built-in catalog
6. **report** - Generate formatted reports from JSON results
7. **diff** - Compare before/after specs

## Architecture

```
agent_spec.yaml
    |
    v
[validate] --> schema + semantic checks
    |
    v
[analyze]  --> rules engine (per layer) + optional LLM evaluation
    |                |
    |                v
    |          AnalyzeReport (findings, scores, attack paths)
    v
[remediate] --> prompt_layer (LLM iterative improvement)
    |           tool_layer   (tool config recommendations)
    |           arch_layer   (architecture recommendations)
    |                |
    |                v
    |          RemediationReport + updated agent_spec.yaml
    v
[simulate] --> catalog scenarios -> attack execution -> judge
    |                |
    |                v
    |          SimulationReport (blocked/succeeded per scenario)
    v
[report]   --> markdown / HTML / JSON output
[diff]     --> before/after comparison
```

## Development Workflow

### Setup

```bash
git clone https://github.com/cybozu/prompt-hardener.git
cd prompt-hardener
uv venv && source .venv/bin/activate
uv pip install -e .
```

### Running Tests

```bash
pytest                     # All tests
pytest tests/test_analyze.py  # Single module
pytest -x                  # Stop on first failure
```

### Linting

```bash
ruff check src/ tests/
```

### CLI Examples

```bash
# Generate a spec from template
prompt-hardener init --type chatbot -o agent_spec.yaml

# Validate the spec
prompt-hardener validate agent_spec.yaml

# Static analysis
prompt-hardener analyze agent_spec.yaml --format markdown

# Static + LLM evaluation
prompt-hardener analyze agent_spec.yaml -ea openai -em gpt-4o-mini

# Remediate (requires LLM)
prompt-hardener remediate agent_spec.yaml -ea openai -em gpt-4o-mini -o hardened.yaml

# Attack simulation (requires LLM)
prompt-hardener simulate agent_spec.yaml -ea openai -em gpt-4o-mini

# Generate report from JSON results
prompt-hardener report results.json -f markdown

# Diff two specs
prompt-hardener diff before.yaml after.yaml
```

## Key Patterns

### Rule System

Rules are registered via the `@rule` decorator in `analyze/rules/`. Each rule function receives an `AgentSpec` and returns a list of `Finding` objects.

```python
@rule(
    id="PROMPT-001",
    name="Missing instruction-data boundary",
    layer="prompt",
    severity="high",
    types=["chatbot", "rag", "agent", "mcp-agent"],
)
def check_boundary(spec: AgentSpec) -> List[Finding]:
    ...
```

Rules are auto-discovered via `_ensure_rules_loaded()` which imports all rule modules. To add a new rule, add a decorated function to the appropriate `*_rules.py` file.

### Data Flow

- `AgentSpec` (from YAML) is the central data model passed through all stages.
- Each engine function returns a typed report dataclass (e.g., `AnalyzeReport`, `RemediationReport`).
- Reports serialize to JSON via `.to_dict()` methods.
- The `report` subcommand reads JSON files back and renders them in different formats.

### Test Conventions

- Tests use `pytest` with fixtures in `tests/fixtures/`.
- LLM-dependent tests should be skippable (most tests use static analysis only).
- Each module (`analyze`, `remediate`, `simulate`, `diff`, `report`) has a corresponding `test_*.py`.

## Backward Compatibility

Legacy commands `evaluate` and `improve` (from v0.4) are preserved and functional. They internally convert the old JSON prompt format to a temporary `AgentSpec` and delegate to the new `analyze` engine with `layers=["prompt"]`.

- `evaluate` -> calls `run_analyze()` with LLM evaluation enabled
- `improve` -> calls the legacy `run_improvement_loop()`

These commands accept the same arguments as before. New users should use the vnext workflow (`init` -> `validate` -> `analyze` -> `remediate` -> `simulate`).