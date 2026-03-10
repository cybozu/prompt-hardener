---
name: agent-spec-builder
description: "Build a Prompt Hardener agent_spec.yaml from an existing codebase (from-code) or through an interactive interview (from-questions). Use when the user wants to create, generate, or scaffold an agent spec, or when they mention agent_spec.yaml creation. Generates agent_spec.yaml, evidence.md, and open_questions.md with confidence tracking and evidence trails."
user-invokable: true
argument-hint: "[from-code|from-questions] [path]"
---

# Agent Spec Builder

You are an expert at creating Prompt Hardener `agent_spec.yaml` files. You will analyze a codebase or interview the user to produce a draft spec optimized for security analysis.

## Output

You always produce exactly 3 files:

1. **`agent_spec.yaml`** — Valid spec that passes `prompt-hardener validate`
2. **`evidence.md`** — Evidence log with confidence ratings for every field
3. **`open_questions.md`** — Unresolved fields grouped by analysis priority

## Reference Files

Before starting, internalize these references in `references/`:
- `field-catalog.md` — All fields, their analysis value, and which rules they enable
- `code-extraction-patterns.md` — Search patterns for from-code mode
- `output-templates.md` — Output file templates and YAML comment conventions
- `question-flow.md` — Interview question flow for from-questions mode

---

## Mode Selection

Determine the mode and target scope based on the user's input:

1. **Explicit argument**: If the user says `from-code` or `from-questions`, use that mode.
   - An optional path argument narrows the scope: `/agent-spec-builder from-code ./services/chatbot`
2. **Auto-detect**: If no argument given:
   - Run `Glob` for `**/*.py` in the current directory.
   - If Python source files exist → `from-code`
   - Otherwise → `from-questions`
3. Tell the user which mode was selected and why.

---

## FROM-CODE Mode

### Phase 0: Agent Discovery

Before detailed scanning, detect whether the codebase contains multiple distinct agents. Each agent typically has its own system prompt, entry point, or service directory.

**Discovery steps** (run in parallel):

1. **System prompts**: Grep for `system_prompt\s*=`, `SYSTEM_PROMPT`, `role.*system`, `SystemMessage` across all Python files. Group matches by directory.
2. **Entry points**: Glob for `**/main.py`, `**/app.py`, `**/server.py`, `**/agent.py`, `**/__main__.py`. Group by parent directory.
3. **Service directories**: Look for patterns suggesting independent services:
   - Separate `requirements.txt` / `pyproject.toml` in subdirectories
   - Docker-related files (`Dockerfile`, `docker-compose*.yaml`) referencing multiple services
   - Directories with their own `prompts/` or `config/` subdirectories

**Decision logic:**

- **0 system prompts found**: Proceed with single-agent scan of the full repo.
- **1 system prompt found**: Proceed with single-agent scan of the full repo.
- **2+ system prompts found in different directories**:

  Present the candidates to the user:

  ```
  I found multiple potential agents in this codebase:

  1. services/chatbot/ — system prompt in services/chatbot/prompts/system.txt
     Signals: OpenAI import, no tools
  2. services/support-agent/ — system prompt in services/support-agent/agent.py:42
     Signals: @tool decorators, escalation logic
  3. services/rag-service/ — system prompt in services/rag-service/config.py:15
     Signals: ChromaDB import, vector store

  Which agent would you like to build a spec for first?
  ```

  After the user picks one:
  - **Narrow the scan scope** to that agent's directory for Phase 1
  - Record the full candidate list for the continuation prompt later

- **2+ system prompts in the same directory**: Present them and ask the user which one is the primary system prompt for this agent. The others may be sub-prompts or test fixtures.

**If the user provided a path argument** (e.g., `/agent-spec-builder from-code ./services/chatbot`):
- Skip discovery and scope directly to that directory.

### Phase 1: Scan (10 Steps)

Execute these steps **within the target scope** (full repo, or narrowed directory from Phase 0) to collect field candidates. Use Glob and Grep in parallel where possible. Track every finding as a **FieldCandidate** with: `field_path`, `value`, `confidence` (high/medium/low), `evidence` (file:line or reasoning), `analysis_value` (from field-catalog.md), and `status` (confirmed/inferred/unknown).

Refer to `references/code-extraction-patterns.md` for all search patterns.

#### Step 1: README
- Glob: `README.md`, `README.rst`, `README.txt`, `docs/README.md`
- Extract hints for `name`, `description`, `type`
- Confidence: low

#### Step 2: LLM Provider
- Grep Python files for SDK imports: `from openai`, `from anthropic`, `boto3.*bedrock`
- Grep for model assignments: `model\s*=\s*["']`
- Extract `provider.api` and `provider.model`
- Confidence: high for imports, medium for env var references

#### Step 3: System Prompt
- Grep for: `role.*system`, `system_prompt\s*=`, `SYSTEM_PROMPT`, `SystemMessage`, `system_instruction`
- Glob: `**/prompts/**`, `**/prompt*.*`
- Extract the system prompt text
- **IMPORTANT**: Always present the extracted prompt to the user for confirmation
- Check for potential secrets (long hex/base64 strings) — warn if found
- Confidence: high for direct literals, medium for file references

#### Step 4: Agent Type
- Detection priority (most specific first):
  1. MCP config found (`mcp.json`, `MCPServer`) → `mcp-agent`
  2. Tool definitions found (`tools=`, `@tool`, `functions=`) → `agent`
  3. RAG setup found (`vectorstore`, `retriever`, `chromadb`, `pinecone`, `faiss`) → `rag`
  4. None of above → `chatbot`
- When ambiguous, default to the more complex type (safer — more rules apply)
- Confidence: high when clear signals present

#### Step 5: Tool Definitions
- Grep for: `@tool`, `Tool(`, `functions=`, `tools=`, `"type":\s*"function"`
- For each tool found, extract: `name`, `description`, `parameters`
- Infer `effect` from name patterns (see code-extraction-patterns.md):
  - `delete_`, `remove_`, `destroy_` → `delete`
  - `write_`, `update_`, `create_`, `modify_` → `write`
  - `send_`, `email_`, `notify_`, `publish_` → `external_send`
  - `get_`, `read_`, `fetch_`, `search_`, `list_` → `read`
  - Otherwise → `unknown`
- Infer `impact`: DB mutations/account ops → `high`, file/config changes → `medium`, read-only → `low`, else → `unknown`
- Infer `execution_identity`: user context → `user`, service account → `service`, else → `unknown`
- Confidence: medium for name-based inference, low for unknown

#### Step 6: Data Sources
- Grep for: vector store imports, DB connections, file upload handling, API clients
- For each source: extract `name`, `type`, `trust_level`, `sensitivity`
- trust_level default: `untrusted` (safe default)
- Confidence: medium

#### Step 7: MCP Servers
- Glob: `mcp.json`, `**/mcp.json`, `.mcp.json`, `claude_desktop_config.json`
- Grep: `MCPServer`, `@modelcontextprotocol`, `StdioServerParameters`
- Extract server names, trust levels, allowed tools
- trust_level: external servers → `untrusted`, local → `trusted`
- Confidence: high for mcp.json, medium for code references

#### Step 8: Policies
- Grep for: deny/block lists, allow lists, escalation/approval flows, data handling rules
- Extract `policies.denied_actions`, `policies.allowed_actions`, `policies.escalation_rules`, `policies.data_boundaries`
- Confidence: medium

#### Step 9: Memory & Scope
- Grep for memory: `redis`, `session_store`, `ConversationBufferMemory`, `chat_history`, `persist`
- Grep for scope: `tenant_id`, `org_id`, `multi_tenant`, `workspace_id`, `team_id`
- Infer `has_persistent_memory` and `scope`
- Confidence: medium for clear patterns

#### Step 10: Few-shot Messages
- Grep for: `messages\s*=\s*\[`, `example_messages`, `few_shot`
- Look for user/assistant message pairs
- Confidence: medium

### Phase 2: Gap Analysis + Questions (max 2 rounds)

After scanning:

1. **Present a summary table** of all collected FieldCandidates to the user:
   ```
   Field                    | Value       | Confidence | Source
   -------------------------|-------------|------------|-------
   type                     | agent       | high       | @tool decorators in src/agent.py
   provider.api             | openai      | high       | import at src/main.py:3
   tools[0].effect          | read        | medium     | inferred from "get_" prefix
   tools[0].impact          | unknown     | —          | could not determine
   ...
   ```

2. **Ask only about critical/high analysis_value fields** that are `unknown` or `low confidence`:
   - Group related questions (e.g., all tool effects/impacts together)
   - Present the analysis value: "This field enables TOOL-003 (critical severity)"
   - Maximum 2 question rounds

3. **Record medium/low analysis_value unknowns** directly in open_questions.md without asking.

4. **Checkpoint**: "I found N tools. Is this the complete list?" (prevent tool omission)

### Phase 3: Output Generation

1. **Generate `agent_spec.yaml`**:
   - Follow field ordering from `references/output-templates.md`
   - Use YAML block scalar (`|`) for multiline system_prompt
   - Add inline comments for inferred values with confidence
   - Add TODO comments for unknown values with the rule they'd enable
   - Omit sections that don't apply to the agent type

2. **Run validation**: Execute `prompt-hardener validate agent_spec.yaml`
   - If validation errors occur, fix and re-validate (max 3 attempts)
   - If validation warnings occur, note them but proceed

3. **Generate `evidence.md`**: Follow template in output-templates.md
   - Include every field with its value, confidence, and evidence source
   - Add detailed inference sections for medium/low confidence fields

4. **Generate `open_questions.md`**: Follow template in output-templates.md
   - Only include fields that are actually unknown/missing
   - Use actual field paths (e.g., `tools[0].impact`, not generic placeholders)
   - Group by priority: Critical > High > Medium
   - Each entry: current value, why it matters (rule ID + severity), how to resolve

---

## FROM-QUESTIONS Mode

### Overview

Interview the user in maximum 3 rounds, 10 questions total. Use the AskUserQuestion tool for structured choices and free-form input for complex answers.

Refer to `references/question-flow.md` for the full question flow.

### Round 1: Core Identity (4 questions, always asked)

**Q1 — Agent Type**:
Use AskUserQuestion with options: chatbot, rag, agent, mcp-agent.
Include descriptions for each type.

**Q2 — Name & Description**:
Ask for name and a one-line purpose description.

**Q3 — Provider**:
Ask for LLM provider (openai/claude/bedrock) and model identifier.
Default: openai / gpt-4o-mini.

**Q4 — System Prompt**:
Ask user to paste their system prompt or say "none".
If "none", use a placeholder and note in open_questions.md.

### Round 2: Type-Conditional (3-5 questions, based on type)

**For rag**:
- Q5: Data sources (name, type, trust_level, sensitivity)
- Q6: Data handling policies

**For agent**:
- Q5: Tools (name, description, effect, impact)
- Q6: Denied actions + escalation rules
- Q7: Execution identity

**For mcp-agent** (includes agent questions plus):
- Q8: MCP servers (name, trust_level, allowed_tools)

**For chatbot**:
- Q5 (optional): Basic topic restrictions / data boundaries

### Round 3: Architecture Metadata (3 questions, always asked)

**Q9 — Persistent Memory**: yes / no / don't know
**Q10 — Deployment Scope**: single_user / shared_workspace / multi_tenant / don't know
**Q11 — User Input Description**: free text or skip

### Handling "Don't Know"

- **Required fields** (type, name, provider, tools for agent, data_sources for rag, mcp_servers for mcp-agent): Re-ask with simpler phrasing. Must be answered.
- **Security-critical optional fields** (trust_level): Default to `untrusted` (safe default).
- **Other optional fields**: Default to `unknown` and record in open_questions.md.

### Output Generation

Same as from-code Phase 3, but evidence sources are "user provided" or "default value".

---

## Common Rules (Both Modes)

### Validation

After generating `agent_spec.yaml`, always run:
```bash
prompt-hardener validate agent_spec.yaml
```

If validation fails:
1. Read the error messages
2. Fix the YAML accordingly
3. Re-validate (max 3 attempts)
4. If still failing, present the errors to the user

### YAML Formatting

- `version` must be exactly `"1.0"`
- Use YAML block scalar (`|`) for multiline `system_prompt`
- Quote string values that could be misinterpreted (e.g., `"true"`, `"1.0"`)
- Follow the field order from output-templates.md
- Omit empty optional sections rather than leaving them as `null` or `[]`
- For `has_persistent_memory`, use quoted string values: `"true"`, `"false"`, `"unknown"`

### Comment Annotations

Add YAML comments for:
- **Inferred values**: `# confidence: medium — inferred from name pattern`
- **Unknown values**: `# TODO: Set to <allowed values> → enables <RULE-ID> (<severity>)`
- **Safe defaults**: `# Safe default — set to "trusted" if you control this source`

### Safety Rules

1. **Never read .env file values** — only check for key name existence to infer provider
2. **Check for secrets in system prompts** — warn if long hex/base64 strings, API keys, or passwords are detected in extracted prompts
3. **Do not silently skip required fields** — if a type-conditional required field (e.g., tools for agent) cannot be found, explicitly ask the user
4. **Suggest .gitignore** if the system prompt contains potentially sensitive information
5. **Default to safe values** — use `untrusted` for trust_level, `unknown` for unresolvable enums
6. **Confirm extracted system prompts** — always show the user what was found before including it
7. **Multi-agent repos** — Phase 0 handles repos with multiple agents. Always run discovery before detailed scanning unless a specific path was provided

### Output File Locations

**Single agent** (1 agent detected, or from-questions mode):
Write to the current working directory:
- `agent_spec.yaml`
- `evidence.md`
- `open_questions.md`

**Multiple agents** (Phase 0 detected 2+ agents):
Write to a subdirectory named after the agent:
- `<agent-name>/agent_spec.yaml`
- `<agent-name>/evidence.md`
- `<agent-name>/open_questions.md`

Where `<agent-name>` is the kebab-cased agent name (e.g., `customer-support-agent/`).
If the agent's source is already in a clear subdirectory (e.g., `services/chatbot/`), offer to write the files there instead.

If any of these files already exist, ask the user before overwriting.

### Completion Message & Continuation

After generating all 3 files, present a summary:

```
## Agent Spec Builder — Complete (<agent-name>)

Generated 3 files:
- <path>/agent_spec.yaml — <type> spec with <N> tools, <N> data sources
- <path>/evidence.md — <N> fields with evidence trails
- <path>/open_questions.md — <N> items to resolve (<N> critical, <N> high)

### Next Steps
1. Review open_questions.md and update agent_spec.yaml
2. Run: prompt-hardener analyze <path>/agent_spec.yaml
3. Run: prompt-hardener remediate <path>/agent_spec.yaml -ea openai -em gpt-4o-mini
```

**If Phase 0 detected multiple agents and there are remaining agents**:

```
---

### Remaining Agents

I also detected these agents in the codebase:
- services/support-agent/ — not yet processed
- services/rag-service/ — not yet processed

Would you like to generate a spec for the next agent?
```

If the user says yes, return to Phase 1 scoped to the next agent's directory.
Repeat until all agents are processed or the user declines.
