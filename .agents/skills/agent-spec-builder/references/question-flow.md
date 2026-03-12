# Question Flow

Interactive question flow for `from-questions` mode. Keep the interview to **3 rounds** and **at most 10 user-facing prompts** by grouping related fields.

---

## Round 1: Core Identity (4 prompts)

### Q1: Agent Type

> What type of agent are you building?

Options:

- **chatbot** — conversational bot without tools or retrieval
- **rag** — retrieval-augmented assistant
- **agent** — tool-calling agent
- **mcp-agent** — tool-calling agent connected to MCP servers

Extract:

- `type`

### Q2: Name And Description

> What is the agent called, and what is its purpose?

Extract:

- `name`
- `description`

### Q3: Provider

> Which LLM provider and model will it use? If Bedrock, include region and profile if applicable.

Extract:

- `provider.api`
- `provider.model`
- `provider.region` when applicable
- `provider.profile` when applicable

Default if skipped: `openai / gpt-4o-mini`

### Q4: System Prompt

> Paste the current system prompt. If you do not have one yet, say `none`.

Extract:

- `system_prompt`

If missing, use `You are a helpful assistant.` and record the placeholder in `open_questions.md`.

---

## Round 2: Type-Conditional Prompts

### For `rag`

#### Q5-rag: Data Sources

> List each data source with: name, type, trust level, and sensitivity.

Extract:

- `data_sources[].name`
- `data_sources[].type`
- `data_sources[].trust_level`
- `data_sources[].sensitivity`

#### Q6-rag: Retrieval Policies

> List any data boundaries or retrieval-handling rules, especially for confidential data or untrusted content.

Extract:

- `policies.data_boundaries`

### For `agent`

#### Q5-agent: Tools

> For each tool, provide: name, description, key parameters, effect, impact, execution identity, and source. If a tool is third-party, include version and content hash if known.

Extract:

- `tools[].name`
- `tools[].description`
- `tools[].parameters`
- `tools[].effect`
- `tools[].impact`
- `tools[].execution_identity`
- `tools[].source`
- `tools[].version`
- `tools[].content_hash`

Also note whether any dangerous parameters are intentionally constrained for TOOL-007.

#### Q6-agent: Policies And Budgets

> What actions are allowed, denied, or require approval? Also include any execution ceilings such as max tool calls, max steps, rate limits, or cost budgets.

Extract:

- `policies.allowed_actions`
- `policies.denied_actions`
- `policies.escalation_rules`
- `policies.max_tool_calls`
- `policies.max_steps`
- `policies.rate_limits`
- `policies.cost_budget`

#### Q7-agent: Data Sources (if any)

> Does the agent retrieve from, read from, or have access to any data sources? If yes, list name, type, trust level, and sensitivity. If none, say `none`.

Extract:

- `data_sources[]` when applicable

### For `mcp-agent`

Ask Q5-agent, Q6-agent, and Q7-agent first, then:

#### Q8-mcp: MCP Servers

> For each MCP server, provide: name, trust level, allowed tools, data access, source, and if not first-party, version and content hash if known.

Extract:

- `mcp_servers[].name`
- `mcp_servers[].trust_level`
- `mcp_servers[].allowed_tools`
- `mcp_servers[].data_access`
- `mcp_servers[].source`
- `mcp_servers[].version`
- `mcp_servers[].content_hash`

### For `chatbot`

#### Q5-chatbot: Policies

> Are there any refusal rules, data boundaries, or topics the chatbot must avoid?

Extract:

- `policies.data_boundaries`

---

## Round 3: Architecture Metadata

### Q8/Q9: Persistent Memory And Protections

Use one prompt for non-MCP agents and the next available prompt index for MCP agents.

> Does the agent persist memory or conversation state across sessions? If yes, what protections exist before storing or reusing that data, such as validation, provenance, TTL, rollback, or segmentation?

Extract:

- `has_persistent_memory`
- evidence for ARCH-005 in `evidence.md`

### Q9/Q10: Scope And Tenant Isolation

Use one prompt for non-MCP agents and the next available prompt index for MCP agents.

> What is the deployment scope: single_user, shared_workspace, or multi_tenant? If it is multi-tenant, what tenant or user isolation controls exist?

Extract:

- `scope`
- tenant-isolation evidence for `evidence.md`
- if missing, add follow-up note tied to ARCH-007

### Q10: User Input Description

> How do users provide input to the agent?

Extract:

- `user_input_description`

---

## Handling "Don't Know" Responses

| Field | Behavior |
|-------|----------|
| `type` | Must be answered |
| `name` | Must be answered; suggest `My Agent` if needed |
| `provider` | Default to `openai / gpt-4o-mini` |
| `system_prompt` | Use placeholder and record follow-up |
| `tools` for `agent` / `mcp-agent` | Must provide at least one |
| `data_sources` for `rag` | Must provide at least one |
| `mcp_servers` for `mcp-agent` | Must provide at least one |
| `trust_level` | Default to `untrusted` |
| `sensitivity` | Default to `unknown` and record follow-up |
| `effect`, `impact`, `execution_identity` | Default to `unknown` and record follow-up |
| `source` | Default to `unknown` and record follow-up |
| `version`, `content_hash` | Leave unset and record follow-up when provenance matters |
| `allowed_actions`, `max_tool_calls`, `max_steps`, `rate_limits`, `cost_budget` | Accept skip and record medium-priority follow-up |
| `denied_actions`, `escalation_rules` | Accept skip and record high-priority follow-up |
| `has_persistent_memory`, `scope` | Default to `unknown` and record follow-up |
| memory protections / tenant isolation evidence | Accept skip and record medium-priority follow-up |
| `user_input_description` | Accept skip and record medium-priority follow-up |

---

## Grouping Strategy

- Ask for tabular or bullet-list answers when collecting tools, data sources, or MCP servers
- Keep provenance and budget questions in the same round as tools/policies
- Do not split execution identity and provenance into separate prompts
- Do not exceed 10 prompts; merge related follow-ups into the same message when needed
