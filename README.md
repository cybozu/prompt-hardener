# Prompt Hardener

Prompt Hardener is an open-source tool that **evaluates and strengthens system prompts** used in LLM-based applications. It helps developers proactively defend against **prompt injection attacks** through automated analysis, layered remediation, and attack simulation.

Define your agent in a unified specification (`agent_spec.yaml`), then run a security pipeline that covers **prompt**, **tool**, and **architecture** layers.

> Designed for:
> - LLM application developers
> - Security engineers working on AI pipelines
> - Prompt engineers and red teamers

## Features

| Feature | Description |
|---------|-------------|
| Agent Specification | Unified YAML format for chatbot, RAG, agent, and MCP-agent types |
| Layered Analysis | Static rules + LLM evaluation across prompt, tool, and architecture layers |
| Iterative Remediation | Three-layer remediation with LLM-driven prompt improvement |
| Attack Simulation | Scenario-based adversarial testing from a built-in catalog (8 categories) |
| Hardening Techniques | Spotlighting, Random Sequence Enclosure, Instruction Defense, and more |
| Multi-format Reports | Markdown, HTML, and JSON reports for CI/CD integration |
| Web UI | Gradio-based interface for interactive experimentation |

## Getting Started

### API Keys

Prompt Hardener uses LLMs to **evaluate** prompts, **apply security improvements**, **test prompt injection attacks**, and **judge whether attacks were successful** — all in an automated pipeline.

Prompt Hardener supports **OpenAI**, **Anthropic Claude** and **AWS Bedrock (Claude v3 or newer)** APIs.

You must set at least one of the following environment variables before use:

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

Run static rule-based analysis. Optionally add LLM-powered evaluation for the prompt layer.

```bash
# Static analysis only
prompt-hardener analyze agent_spec.yaml --format markdown

# Static + LLM evaluation
prompt-hardener analyze agent_spec.yaml \
  -ea openai -em gpt-4o-mini \
  --format both -o report.json
```

Use `--layers prompt tool architecture` to filter which layers to analyze. See `prompt-hardener analyze --help` for all options.

### 4. remediate

Generate actionable remediations across three layers. The prompt layer uses LLM-driven iterative improvement; tool and architecture layers produce recommendations.

```bash
prompt-hardener remediate agent_spec.yaml \
  -ea openai -em gpt-4o-mini \
  -o hardened.yaml \
  -rd ./reports
```

Options: `--layers`, `--max-iterations`, `--threshold`, `--apply-techniques`. See `prompt-hardener remediate --help`.

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

The agent specification is a YAML file that describes the agent under test. It is the single input for all vnext commands.

### Agent Types

| Type | Description | Analyzed Layers |
|------|-------------|-----------------|
| `chatbot` | Simple conversational bots | prompt |
| `rag` | Retrieval-augmented generation systems | prompt, architecture |
| `agent` | Tool-calling agents | prompt, tool, architecture |
| `mcp-agent` | MCP server-connected agents | prompt, tool, architecture |

### Field Requirements

| Field | chatbot | rag | agent | mcp-agent |
|-------|---------|-----|-------|-----------|
| `version` | required | required | required | required |
| `type` | required | required | required | required |
| `name` | required | required | required | required |
| `system_prompt` | required | required | required | required |
| `provider` | required | required | required | required |
| `description` | optional | optional | optional | optional |
| `messages` | optional | optional | optional | optional |
| `tools` | - | - | required | required |
| `policies` | optional | optional | recommended | recommended |
| `data_sources` | - | recommended | optional | optional |
| `mcp_servers` | - | - | - | required |
| `user_input_description` | optional | optional | optional | optional |

### Examples

**Minimal chatbot** (`examples/chatbot-minimal/agent_spec.yaml`):

```yaml
version: "1.0"
type: chatbot
name: "FAQ Bot"
description: "Simple FAQ chatbot for product questions"

system_prompt: |
  You are a friendly FAQ assistant for Acme Corp.
  Answer questions about our products based on your training data.
  If you don't know the answer, say "I'm not sure about that, please contact support."
  Do not make up information or provide advice outside your knowledge.

provider:
  api: openai
  model: gpt-4o-mini

user_input_description: "Customer questions submitted through web chat widget"
```

**RAG assistant** (`examples/rag-internal-assistant/agent_spec.yaml`):

```yaml
version: "1.0"
type: rag
name: "Internal Documentation Assistant"

system_prompt: |
  You are an internal documentation assistant for Acme Corp employees.
  Answer questions strictly based on the retrieved documents provided to you.
  If the documents don't contain the answer, say "I couldn't find this in the documentation."
  Never fabricate information. Always cite which document your answer comes from.

provider:
  api: openai
  model: gpt-4o-mini

data_sources:
  - name: confluence_docs
    type: vector_store
    trust_level: trusted
  - name: employee_uploads
    type: file_input
    trust_level: untrusted
```

**Agent with tools** (`examples/agent-basic/agent_spec.yaml`):

```yaml
version: "1.0"
type: agent
name: "Customer Support Agent"

system_prompt: |
  You are a customer support agent for Acme Corp.
  Help customers with their inquiries using the available tools.
  Always verify the customer's identity before accessing account information.

provider:
  api: openai
  model: gpt-4o-mini

tools:
  - name: get_order_status
    description: "Retrieve the current status of a customer order"
    parameters:
      type: object
      properties:
        order_id:
          type: string
      required: [order_id]

policies:
  allowed_actions: [get_order_status, search_knowledge_base]
  denied_actions: [delete_account, modify_billing]
  escalation_rules:
    - condition: "Customer requests account deletion"
      action: "Escalate to human agent"
```

See the `examples/` directory for complete examples.

## Attack Simulation

### Built-in Catalog

Prompt Hardener includes a built-in catalog of attack scenarios organized by category:

| Category | Description | Target Layer |
|----------|-------------|--------------|
| Persona Switching | Attempts to override the agent's role and persona | prompt |
| Output Attack | Tries to manipulate the agent's output format or behavior | prompt |
| Prompt Leaking | Attempts to extract the system prompt | prompt |
| Chain-of-Thought Escape | Exploits reasoning to bypass instructions | prompt |
| Function Call Hijacking | Tricks the agent into calling unintended tools | tool |
| Ignoring RAG Instructions | Attempts to ignore or override retrieved context | prompt |
| Privilege Escalation | Tries to gain unauthorized access or capabilities | architecture |
| Tool Definition Leaking | Attempts to extract tool definitions and schemas | tool |

Each scenario specifies payloads, success criteria, and applicable agent types.

### Custom Scenarios

Point to a directory of custom YAML scenario files:

```bash
prompt-hardener simulate agent_spec.yaml \
  -ea openai -em gpt-4o-mini \
  --scenarios ./my_scenarios/
```

## Hardening Techniques

Prompt Hardener includes multiple defense strategies:

| Technique | Description |
|-----------|-------------|
| **Spotlighting** | Explicitly marks and isolates all user-controlled input using tags and special characters to prevent injection. |
| **Random Sequence Enclosure** | Encloses trusted system instructions in unpredictable tags, ensuring only those are followed and not leaked. |
| **Instruction Defense** | Instructs the model to ignore new instructions, persona switching, or attempts to reveal/modify system prompts. |
| **Role Consistency** | Ensures each message role (system, user, assistant) is preserved and not mixed, preventing role confusion attacks. |
| **Secrets Exclusion** | Ensure that no sensitive information is hardcoded in the prompt. |

See [docs/techniques.md](./docs/techniques.md) for details on each technique.

## Layered Remediation

The `remediate` command applies fixes across three layers:

| Layer | What It Does | Requires LLM |
|-------|-------------|--------------|
| **Prompt** | Iteratively improves the system prompt using LLM evaluation feedback. Applies hardening techniques, reinforces boundaries, and strengthens instructions. | Yes |
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

## Legacy Commands (v0.4.0 Compatible)

The `evaluate` and `improve` commands from v0.4.0 are still supported for backward compatibility. New users should use the vnext workflow above.

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

See examples of using Prompt Hardener to improve and test system prompts:

[docs/tutorials.md](./docs/tutorials.md)
