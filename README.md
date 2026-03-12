# Prompt Hardener

Prompt Hardener analyzes **prompt-injection-originated risk in LLM-based agents and applications**.

Define your system in a unified specification (`agent_spec.yaml`), then run a multi-layer security pipeline that:

- analyzes structural risks across prompts, context sources, and tools  
- validates behavior with adversarial attack scenarios  
- proposes mitigations across **prompt, policy, and architecture layers**

Prompt Hardener helps developers and security engineers understand **how prompt injection could affect their system and how to reduce that risk**.

## Features

| Feature | Description |
|---------|-------------|
| Agent Specification | Unified YAML format for chatbot, RAG, agent, and MCP-agent types |
| Layered Analysis | Deterministic static rules across prompt, tool, and architecture layers |
| Conservative Remediation | Three-layer remediation with planner-driven constrained prompt rewriting |
| Attack Simulation | Scenario-based adversarial testing from a built-in catalog |
| Hardening Techniques | Spotlighting, Random Sequence Enclosure, Instruction Defense, and more |
| Multi-format Reports | Markdown, HTML, and JSON reports for CI/CD integration |
| Web UI | Gradio-based interface for interactive experimentation |

## Getting Started

### API Keys

Most of the standard workflow does **not** require an API key. `init`, `validate`, `analyze`, `report`, and `diff` are deterministic commands.

LLM credentials are only needed for LLM-backed operations:

- prompt-layer `remediate`
- `simulate`

Prompt Hardener supports **OpenAI**, **Anthropic Claude** and **AWS Bedrock (Claude v3 or newer)** APIs for LLM-backed commands.

You must set at least one of the following environment variables before using those commands:

```bash
# For OpenAI API (e.g., GPT-4, GPT-4o)
export OPENAI_API_KEY=...

# For Claude API (e.g., Claude 3.7 Sonnet)
export ANTHROPIC_API_KEY=...

# For Bedrock API (e.g., anthropic.claude-3-5-sonnet-20240620-v1:0)
# Option 1: Use AWS Profile (recommended)
aws configure --profile my-profile
# Then use --aws-profile my-profile in the command

# Option 2: Use environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

You can add these lines to your shell profile (e.g., `.bashrc`, `.zshrc`) to make them persistent.

### Installation

```bash
# Option 1 (Recommended): Install as a CLI tool using uv
uv tool install \
  https://github.com/cybozu/prompt-hardener/releases/download/vX.Y.Z/prompt_hardener-X.Y.Z-py3-none-any.whl

# Option 2: Development / editable install
git clone https://github.com/cybozu/prompt-hardener.git
cd prompt-hardener

uv venv
source .venv/bin/activate
uv pip install -e .
```

## Workflow

Prompt Hardener follows a structured security pipeline:

```
init -> validate -> analyze -> remediate -> simulate -> report -> diff
```

### 1. init

Generate an `agent_spec.yaml` from a built-in template.

```bash
prompt-hardener init --type chatbot -o agent_spec.yaml
prompt-hardener init --type rag -o agent_spec.yaml
prompt-hardener init --type agent -o agent_spec.yaml
prompt-hardener init --type mcp-agent -o agent_spec.yaml
```

Edit the generated file to describe your agent, then validate it.

### 2. validate

Run schema and semantic validation on your spec.

```bash
prompt-hardener validate agent_spec.yaml
```

### 3. analyze

Run deterministic static rule-based analysis.

```bash
prompt-hardener analyze agent_spec.yaml --format markdown
```

Use `--layers prompt tool architecture` to filter which layers to analyze. See `prompt-hardener analyze --help` for all options.

See [docs/analysis-rules.md](./docs/analysis-rules.md) for the full static rule catalog and scoring details.

### 4. remediate

Generate actionable remediations across three layers. The prompt layer uses planner-driven constrained rewriting with deterministic acceptance.

```bash
prompt-hardener remediate agent_spec.yaml \
  -ea openai -em gpt-4o-mini \
  -o hardened.yaml \
  -rd ./reports
```

Options: `--layers`, `--apply-techniques`. See `prompt-hardener remediate --help`.

If you run only `--layers tool architecture`, remediation stays deterministic and does not make LLM calls.

### 5. simulate

Run attack scenarios from the built-in catalog against your agent spec.

```bash
prompt-hardener simulate agent_spec.yaml \
  -ea openai -em gpt-4o-mini \
  -o simulation_results.json
```

Filter by category or layer:

```bash
prompt-hardener simulate agent_spec.yaml \
  -ea openai -em gpt-4o-mini \
  --categories "persona_switch,prompt_leaking" \
  --layers "prompt,tool"
```

See `prompt-hardener simulate --help` for all options including separate attack/judge models.

### 6. report

Generate a formatted report from any JSON output (analyze, remediate, or simulate).

```bash
prompt-hardener report results.json -f markdown
prompt-hardener report results.json -f html -o report.html
```

### 7. diff

Compare two agent specs to see what changed (useful for before/after remediation).

```bash
prompt-hardener diff before.yaml after.yaml
prompt-hardener diff before.yaml after.yaml -f markdown
```

## Agent Specification (agent_spec.yaml)

The agent specification is a YAML file that describes the agent under test. It is the single input for the standard command workflow. Four agent types are supported:

| Type | Description | Analyzed Layers |
|------|-------------|-----------------|
| `chatbot` | Simple conversational bots | prompt |
| `rag` | Retrieval-augmented generation systems | prompt, architecture |
| `agent` | Tool-calling agents | prompt, tool, architecture |
| `mcp-agent` | MCP server-connected agents | prompt, tool, architecture |

See [docs/agent-spec.md](./docs/agent-spec.md) for field requirements, detailed field descriptions, and full examples for each agent type.

## Attack Simulation

Run adversarial attack scenarios against your agent spec to validate prompt injection defenses. The built-in catalog covers 13 categories across three layers (prompt, tool, architecture), including persona switching, prompt leaking, function call hijacking, data source poisoning, and more.

You can also create custom scenarios using YAML files.

See [docs/attack-simulation.md](./docs/attack-simulation.md) for the full catalog, how simulation works, and how to write custom scenarios.

## Hardening Techniques

Prompt Hardener supports five prompt-layer hardening techniques: **Spotlighting**, **Random Sequence Enclosure**, **Instruction Defense**, **Role Consistency**, and **Secrets Exclusion**.

See [docs/techniques.md](./docs/techniques.md) for how each technique works, evaluation criteria, and examples.

## Layered Remediation

The `remediate` command applies fixes across three layers:

| Layer | What It Does | Requires LLM |
|-------|-------------|--------------|
| **Prompt** | Uses a planner-driven constrained rewrite. Selected techniques are normally required for an accepted rewrite. | Yes |
| **Tool** | Analyzes tool definitions and policies. Recommends adding parameter validation, restricting allowed actions, and tightening schemas. | No |
| **Architecture** | Reviews data sources, trust boundaries, and escalation rules. Recommends trust level adjustments, data boundary enforcement, and escalation policies. | No |

## Reporting

After each command (`analyze`, `remediate`, `simulate`), results are output as JSON. Use the `report` command to convert them:

```bash
# Markdown to stdout
prompt-hardener report results.json -f markdown

# HTML file
prompt-hardener report results.json -f html -o report.html
```

Reports include:
- Findings with severity levels and recommended fixes
- Layer-by-layer scores
- Attack simulation results (blocked/succeeded stats)

## Web UI (Gradio)

```bash
prompt-hardener webui
```

Then visit http://localhost:7860 to use Prompt Hardener interactively:
- Paste prompts
- Choose models & settings
- Download hardened prompt and reports

<img width="1544" alt="webui" src="https://github.com/user-attachments/assets/406afba7-9c90-4342-a2ec-c730031c3cd9" />

## Tutorials

Step-by-step walkthroughs for hardening a chatbot and a tool-calling agent:

[docs/tutorials.md](./docs/tutorials.md)

## Legacy Commands (v0.4.0 Compatible)

The `evaluate` and `improve` commands from v0.4.0 are still supported for backward compatibility. New users should use the workflow above.

<details>
<summary>Arguments Overview for evaluate Command</summary>

| Argument                   | Short | Type        | Required | Default             | Description                                                                                                              |
| -------------------------- | ----- | ----------- | -------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `--target-prompt-path`     | `-t`  | `str`       | Yes    | -                   | Path to the file containing the target system prompt (Chat Completion message format, JSON).                             |
| `--input-mode`             |       | `str`       | No     | `chat`              | Prompt format type: `chat` for role-based messages, `completion` for single prompt string.                               |
| `--input-format`           |       | `str`       | No     | `openai`            | Input message format to parse: `openai`, `claude`, or `bedrock`.                                                         |
| `--eval-api-mode`          | `-ea` | `str`       | Yes    | -                   | LLM API used for evaluation (`openai`, `claude` or `bedrock`).                                                           |
| `--eval-model`             | `-em` | `str`       | Yes    | -                   | Model name used for evaluation (e.g., `gpt-4o-mini`, `claude-3-7-sonnet-latest`).                        |
| `--aws-region`             | `-ar` | `str`       | No     | `us-east-1`         | AWS region for Bedrock API mode.                                                                 |
| `--aws-profile`            | `-ap` | `str`       | No     | `None`              | AWS profile name for Bedrock API mode.                             |
| `--user-input-description` | `-ui` | `str`       | No     | `None`              | Description of user input fields.                   |
| `--output-path`            | `-o`  | `str`       | No    | -                   | File path to write the evaluation result as JSON.                                                                        |
| `--apply-techniques`       | `-a`  | `list[str]` | No     | All techniques      | Defense techniques to apply.                                                                         |
| `--report-dir`             | `-rd` | `str`       | No     | `None`              | Directory to write evaluation report files.                            |

Example:

```bash
prompt-hardener evaluate \
  --input-mode chat \
  --input-format openai \
  --target-prompt-path path/to/prompt.json \
  --eval-api-mode openai \
  --eval-model gpt-4o-mini \
  --output-path path/to/evaluation.json
```

</details>

<details>
<summary>Arguments Overview for improve Command</summary>

| Argument                   | Short | Type        | Required | Default             | Description                                                                                                              |
| -------------------------- | ----- | ----------- | -------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `--target-prompt-path`     | `-t`  | `str`       | Yes    | -                   | Path to the file containing the target system prompt (Chat Completion message format, JSON).                             |
| `--input-mode`             |       | `str`       | No     | `chat`              | Prompt format type: `chat` for role-based messages, `completion` for single prompt string.                               |
| `--input-format`           |       | `str`       | No     | `openai`            | Input message format to parse: `openai`, `claude`, or `bedrock`.                                                         |
| `--eval-api-mode`          | `-ea` | `str`       | Yes    | -                   | LLM API used for evaluation and improvement.                                           |
| `--eval-model`             | `-em` | `str`       | Yes    | -                   | Model name used for evaluation and improvement.                        |
| `--attack-api-mode`        | `-aa` | `str`       | No     | `--eval-api-mode`   | LLM API used for executing attacks.                                                     |
| `--attack-model`           | `-am` | `str`       | No     | `--eval-model`      | Model used to generate and run attacks.                                               |
| `--judge-api-mode`         | `-ja` | `str`       | No     | `--eval-api-mode`   | LLM API used for attack judging.                                 |
| `--judge-model`            | `-jm` | `str`       | No     | `--eval-model`      | Model used to judge injection success.                     |
| `--aws-region`             | `-ar` | `str`       | No     | `us-east-1`         | AWS region for Bedrock API mode.                                                                 |
| `--aws-profile`            | `-ap` | `str`       | No     | `None`              | AWS profile name for Bedrock API mode.                             |
| `--user-input-description` | `-ui` | `str`       | No     | `None`              | Description of user input fields.                   |
| `--output-path`            | `-o`  | `str`       | No    | -                   | File path to write the final improved prompt as JSON.                                                                    |
| `--max-iterations`         | `-n`  | `int`       | No     | `3`                 | Maximum number of improvement iterations.                                                                                |
| `--threshold`              |       | `float`     | No     | `8.5`               | Score threshold (0-10) to stop refinement early.                                                 |
| `--apply-techniques`       | `-a`  | `list[str]` | No     | All techniques      | Defense techniques to apply.                                                                         |
| `--test-after`             | `-ta` | `flag`      | No     | `False`             | Run prompt injection test after improvement.                             |
| `--test-separator`         | `-ts` | `str`       | No     | `None`              | Optional string to prepend to each attack payload.                         |
| `--tools-path`             | `-tp` | `str`       | No     | `None`              | Path to JSON file defining available tools for attack testing.                      |
| `--report-dir`             | `-rd` | `str`       | No     | `None`              | Directory to write report files.  |

Example:

```bash
prompt-hardener improve \
  --input-mode chat \
  --input-format openai \
  --target-prompt-path path/to/prompt.json \
  --eval-api-mode openai \
  --eval-model gpt-4o-mini \
  --output-path path/to/hardened.json \
  --user-input-description Comments \
  --max-iterations 3 \
  --test-after \
  --report-dir ~/Downloads
```

</details>
