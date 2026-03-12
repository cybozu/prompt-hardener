---
name: agent-spec-builder
description: "Build a Prompt Hardener agent_spec.yaml from an existing codebase (from-code) or through an interactive interview (from-questions). Use when the user wants to create, generate, or scaffold an agent spec, or when they mention agent_spec.yaml creation. Generates agent_spec.yaml, evidence.md, and open_questions.md with confidence tracking and evidence trails."
user-invokable: true
argument-hint: "[from-code|from-questions] [path]"
---

# Agent Spec Builder

You create Prompt Hardener `agent_spec.yaml` files that are optimized for current static analysis and remediation.

## Output

You always produce exactly 3 files:

1. **`agent_spec.yaml`** — Valid spec that passes `prompt-hardener validate`
2. **`evidence.md`** — Evidence log with confidence ratings for every populated or inferred field
3. **`open_questions.md`** — Unresolved fields grouped by analysis priority

## Source Of Truth

This skill is meant to be portable. Treat the bundled files in `references/` as the primary source of truth:

- `field-catalog.md` — Field inventory, analysis value, and enabled rules
- `code-extraction-patterns.md` — Search patterns for from-code mode
- `output-templates.md` — Output templates and YAML comment conventions
- `question-flow.md` — Interview flow for from-questions mode

If repository docs such as `docs/agent-spec.md` or `docs/analysis-rules.md` are available, use them only as an optional cross-check. Do not assume they exist.

## General Rules

- Only write schema-supported fields into `agent_spec.yaml`.
- Put provenance evidence, detection rationale, and unresolved risk notes into `evidence.md` or `open_questions.md`, not into ad hoc YAML fields.
- Keep confidence explicit for every inferred value.
- Use current rule IDs only. Never mention deprecated or nonexistent rule IDs.

---

## Mode Selection

Determine the mode and scope from the user's input:

1. If the user explicitly says `from-code` or `from-questions`, use that mode.
2. If the user passes a path, scope the scan or interview to that path.
3. Otherwise auto-detect:
   - If the target contains Python source files, use `from-code`
   - If not, use `from-questions`
4. Tell the user which mode you selected and why.

---

## FROM-CODE Mode

### Phase 0: Agent Discovery

Before deep scanning, detect whether the repo contains multiple distinct agents.

Run these checks in parallel:

1. **System prompt signals**: search for `system_prompt`, `SYSTEM_PROMPT`, `role.*system`, `SystemMessage`, `system_instruction`
2. **Entrypoints**: search for `main.py`, `app.py`, `server.py`, `agent.py`, `__main__.py`
3. **Service boundaries**: look for subdirectories with their own `pyproject.toml`, `requirements.txt`, `Dockerfile`, `prompts/`, or `config/`

Decision logic:

- If prompts are absent or only one candidate exists, scan the full scope.
- If multiple plausible agents exist in different directories, present the candidates and ask the user which one to spec first.
- If multiple prompt candidates exist in one directory, ask which one is the primary system prompt.
- If the user passed an explicit path, skip discovery and scan only that path.

### Phase 1: Scan

Track every finding as a `FieldCandidate` with:

- `field_path`
- `value`
- `confidence` (`high` / `medium` / `low`)
- `evidence` (file:line or reasoning)
- `analysis_value`
- `status` (`confirmed` / `inferred` / `unknown`)

Use the patterns in `references/code-extraction-patterns.md`.

#### Step 1: README / Docs

- Extract hints for `name`, `description`, and `type`
- Treat README-derived values as low confidence unless corroborated elsewhere

#### Step 2: Provider

- Extract `provider.api`, `provider.model`, and for Bedrock also `provider.region` / `provider.profile`
- Prefer direct client initialization or config literals over environment variable names

#### Step 3: System Prompt

- Extract the actual prompt text from literals, prompt files, or config loaders
- Always show the extracted prompt to the user for confirmation
- Warn if the prompt appears to contain secrets or internal-only material
- Record prompt-file provenance in `evidence.md` if the prompt is loaded from disk or remote storage

#### Step 4: Agent Type

Detection priority:

1. MCP config or MCP server code -> `mcp-agent`
2. Tool definitions -> `agent`
3. Retrieval/vector store/data-source signals -> `rag`
4. Otherwise -> `chatbot`

If both tools and retrieval are present, prefer `agent`.

#### Step 5: Tools

For each tool, collect or infer:

- `name`
- `description`
- `parameters`
- `effect`
- `impact`
- `execution_identity`
- `source`
- `version`
- `content_hash`

Also collect evidence for:

- dangerous free-form parameters relevant to TOOL-007
- duplicate, confusing, or overly generic tool names relevant to TOOL-008
- third-party provenance gaps relevant to ARCH-009

If `source` is `third_party`, try to resolve `version` and `content_hash`; if you cannot, keep the fields unresolved and record the gap.

#### Step 6: Data Sources

For each data source, collect or infer:

- `name`
- `type`
- `trust_level`
- `description`
- `sensitivity`

Use `untrusted` as the safe default only when trust genuinely cannot be established.

#### Step 7: MCP Servers

For each MCP server, collect or infer:

- `name`
- `trust_level`
- `allowed_tools`
- `data_access`
- `source`
- `version`
- `content_hash`

Also capture whether the server is bundled/first-party, remote, or externally sourced for ARCH-009 evidence.

#### Step 8: Policies

Collect or infer:

- `policies.allowed_actions`
- `policies.denied_actions`
- `policies.data_boundaries`
- `policies.escalation_rules`
- `policies.max_tool_calls`
- `policies.max_steps`
- `policies.rate_limits`
- `policies.cost_budget`

Prefer explicit ceilings found in code or config over prompt-only hints.

#### Step 9: Memory, Scope, And Isolation

Collect or infer:

- `has_persistent_memory`
- `scope`

Also collect evidence for:

- memory poisoning protections relevant to ARCH-005
- tenant or user isolation relevant to ARCH-007

Store those protection details in `evidence.md`, and when missing record the unresolved follow-up in `open_questions.md`.

#### Step 10: Few-Shot Messages

- Extract `messages` examples when they are clearly production-relevant
- Exclude system messages from `messages`
- Treat test fixtures as low confidence unless the user confirms they are representative

### Phase 2: Gap Analysis And User Questions

After scanning:

1. Present a summary table of collected candidates with confidence and source.
2. Ask about unresolved or low-confidence **critical/high** fields first.
3. Group questions to keep the follow-up compact.
4. Use current priority:
   - Critical: `tools[].impact`, `tools[].effect`
   - High: `tools[].execution_identity`, tool/MCP provenance fields, `policies.denied_actions`, `policies.escalation_rules`, `data_sources[].sensitivity`, `has_persistent_memory`, `scope`
   - Medium or lower: allowlists, budgets, user input description, dangerous parameter constraints, tenant-isolation wording
5. Ask explicit completeness checkpoints when relevant:
   - "I found N tools. Is that the full set?"
   - "I found N data sources. Is that the full set?"
   - "I found N MCP servers. Is that the full set?"

### Phase 3: Output Generation

1. Generate `agent_spec.yaml`
   - Follow `references/output-templates.md`
   - Use YAML block scalars for multiline prompts
   - Add inline confidence or TODO comments only for schema-supported fields
   - Omit type-irrelevant sections
2. Run `prompt-hardener validate agent_spec.yaml`
   - Fix validation errors and re-validate, up to 3 attempts
   - Keep warnings, but document them in `evidence.md`
3. Generate `evidence.md`
   - Include every populated/inferred field
   - Include provenance evidence, budget evidence, memory protection evidence, and tenant isolation evidence when applicable
4. Generate `open_questions.md`
   - Include only unresolved or low-confidence fields that materially affect analysis
   - Use actual field paths
   - Use current rule IDs only
   - Group by priority

---

## FROM-QUESTIONS Mode

Use the grouped question flow in `references/question-flow.md`.

Rules:

- Keep the interview to 3 rounds and at most 10 user-facing prompts
- Group related fields into structured prompts instead of asking one field at a time
- If the agent has tools, collect provenance and budget information in the same round
- If the agent is multi-tenant, ask for tenant isolation controls in the same prompt where scope is confirmed
- If the agent has persistent memory, ask for memory-poisoning protections in the same prompt where memory is confirmed
- If the user says "don't know", apply the documented safe default and record the unresolved field in `open_questions.md`

For tool-bearing agents, do not stop at tool names. Collect enough detail to support:

- TOOL-003 (`impact`)
- TOOL-004 (`execution_identity`)
- TOOL-007 (`parameters` constraints)
- TOOL-008 (naming ambiguity / provenance context)
- ARCH-008 (budgets)
- ARCH-009 (provenance metadata)

For MCP agents, collect enough detail to support:

- ARCH-002 (`trust_level`, `allowed_tools`)
- ARCH-004 (`trust_level`)
- ARCH-009 (`source`, `version`, `content_hash`)

For agents with memory or shared scope, collect enough detail to support:

- ARCH-005 (memory protection evidence)
- ARCH-006 (`scope` with sensitive tools)
- ARCH-007 (tenant isolation evidence)

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
