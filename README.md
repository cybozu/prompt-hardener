# Prompt Hardener

Prompt Hardener analyzes **prompt-injection risk in LLM-based agents and applications**.

It gives you a single workflow to:

- describe your system in `agent_spec.yaml`
- run deterministic security analysis across prompt, tool, and architecture layers
- generate mitigations
- validate defenses with adversarial attack simulation
- export results as Markdown, HTML, or JSON

Prompt Hardener is designed for developers and security engineers who want to understand **how prompt injection can affect an agent** and **how to reduce that risk**.

## Why use it?

- **One spec for multiple agent types**: chatbot, RAG, tool-calling agent, and MCP agent
- **Deterministic first**: `init`, `validate`, `analyze`, `report`, and `diff` do not require an LLM API key
- **Layered security view**: inspect prompt, tool, and architecture risks separately
- **Practical remediation**: get recommended fixes for prompts, policies, tools, and trust boundaries
- **Attack validation**: test your spec against built-in adversarial scenarios
- **CI-friendly output**: export Markdown, HTML, or JSON
- **Interactive UI**: explore the workflow from a local Gradio app

## Quick start

The fastest way to try Prompt Hardener is to use one of the included example specs.

### 1) Install

```bash
# Option 1: Install from source
git clone https://github.com/cybozu/prompt-hardener.git
cd prompt-hardener

uv venv
source .venv/bin/activate
uv pip install -e .

# Option 2: Install as a CLI tool using uv
uv tool install \
  https://github.com/cybozu/prompt-hardener/releases/download/vX.Y.Z/prompt_hardener-X.Y.Z-py3-none-any.whl
```

### 2) Analyze an example spec

```bash
cp examples/chatbot-minimal/agent_spec.yaml ./agent_spec.yaml

prompt-hardener validate agent_spec.yaml
prompt-hardener analyze agent_spec.yaml --format markdown
```

That gives you a complete static analysis run without setting any API credentials.

### 3) Export a shareable report

```bash
prompt-hardener analyze agent_spec.yaml -o analyze.json
prompt-hardener report analyze.json -f html -o report.html
```

## When do you need LLM API keys?

Most of the workflow is deterministic.

| Command | API key required? | Notes |
|---|---|---|
| `init` | No | Generate a starter `agent_spec.yaml` |
| `validate` | No | Schema + semantic validation |
| `analyze` | No | Static rule-based analysis |
| `report` | No | Render JSON results as Markdown / HTML / JSON |
| `diff` | No | Compare two specs |
| `remediate` | Sometimes | Prompt-layer remediation needs an LLM; `--layers tool architecture` stays deterministic |
| `simulate` | Yes | Attack simulation is LLM-backed |

Prompt Hardener supports these providers for LLM-backed commands:

- OpenAI
- Anthropic Claude
- AWS Bedrock (Claude v3 or newer)

### Example environment variables

```bash
# OpenAI
export OPENAI_API_KEY=...

# Anthropic Claude
export ANTHROPIC_API_KEY=...

# AWS Bedrock (alternative: use an AWS profile)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

## Your first real workflow

Once you are ready to analyze your own system, the standard workflow is:

```text
init -> validate -> analyze -> remediate -> simulate -> report -> diff
```

### Create a starter spec

```bash
prompt-hardener init --type chatbot -o agent_spec.yaml
prompt-hardener init --type rag -o agent_spec.yaml
prompt-hardener init --type agent -o agent_spec.yaml
prompt-hardener init --type mcp-agent -o agent_spec.yaml
```

Edit the generated file to match your system, then run the rest of the pipeline.

### Validate

```bash
prompt-hardener validate agent_spec.yaml
```

### Analyze

```bash
prompt-hardener analyze agent_spec.yaml --format markdown
```

To limit analysis to specific layers:

```bash
prompt-hardener analyze agent_spec.yaml --layers prompt tool architecture
```

### Remediate

```bash
prompt-hardener remediate agent_spec.yaml \
  -ea openai -em gpt-4o-mini \
  -o hardened.yaml \
  -rd ./reports
```

If you only want deterministic remediation suggestions for non-prompt layers:

```bash
prompt-hardener remediate agent_spec.yaml \
  --layers tool architecture \
  -ea openai -em gpt-4o-mini
```

### Simulate attacks

```bash
prompt-hardener simulate hardened.yaml \
  -ea openai -em gpt-4o-mini \
  -o simulation.json
```

Filter simulation by category or layer when you want a focused test:

```bash
prompt-hardener simulate hardened.yaml \
  -ea openai -em gpt-4o-mini \
  --categories "persona_switch,prompt_leaking" \
  --layers "prompt,tool" \
  -o simulation.json
```

### Compare before and after

```bash
prompt-hardener diff agent_spec.yaml hardened.yaml
```

## Supported agent types

| Type | Description | Analyzed layers |
|---|---|---|
| `chatbot` | Simple conversational bots | prompt |
| `rag` | Retrieval-augmented generation systems | prompt, architecture |
| `agent` | Tool-calling agents | prompt, tool, architecture |
| `mcp-agent` | MCP-connected agents | prompt, tool, architecture |

## What goes into `agent_spec.yaml`?

`agent_spec.yaml` is the single input to the main workflow.

At minimum, you describe:

- the agent type
- the system prompt
- the provider/model
- optional tools, policies, data sources, or MCP servers depending on agent type

For complete field definitions and full examples, see [docs/agent-spec.md](./docs/agent-spec.md).

## Included examples

Use these to understand the spec format and try the tool quickly:

- `examples/chatbot-minimal`
- `examples/rag-internal-assistant`
- `examples/agent-basic`

## Hardening techniques

Prompt-layer remediation can apply these techniques:

- `spotlighting`
- `random_sequence_enclosure`
- `instruction_defense`
- `role_consistency`
- `secrets_exclusion`

See [docs/techniques.md](./docs/techniques.md) for details and examples.

## Attack simulation

The simulator runs adversarial scenarios against your spec so you can validate defenses, not just lint configuration.

See [docs/attack-simulation.md](./docs/attack-simulation.md) for the built-in catalog and custom scenario format.

## Reports

After `analyze`, `remediate`, or `simulate`, you can render JSON results into a friendlier format:

```bash
prompt-hardener report results.json -f markdown
prompt-hardener report results.json -f html -o report.html
```

## Web UI

```bash
prompt-hardener webui
```

Then open `http://localhost:7860` in your browser.

## Documentations

- Rule catalog: [docs/analysis-rules.md](./docs/analysis-rules.md)
- Agent spec reference: [docs/agent-spec.md](./docs/agent-spec.md)
- Attack simulation: [docs/attack-simulation.md](./docs/attack-simulation.md)
- Techniques: [docs/techniques.md](./docs/techniques.md)
- Tutorials: [docs/tutorials.md](./docs/tutorials.md)

## Legacy commands

`evaluate` and `improve` are still available for backward compatibility with v0.4.0 workflows.

New users should start with the spec-based workflow above. For legacy usage details, run:

```bash
prompt-hardener evaluate --help
prompt-hardener improve --help
```

## License

Apache-2.0
