# Question Flow

Interactive question flow for the `from-questions` mode. Maximum 3 rounds, 10 questions total.

---

## Round 1: Core Identity (Always asked — 4 questions)

### Q1: Agent Type

> What type of agent are you building?

Options (present with descriptions):
- **chatbot** — A conversational bot with no tool access or external data retrieval
- **rag** — A retrieval-augmented generation system that answers from documents/data
- **agent** — A tool-calling agent that can perform actions via function calls
- **mcp-agent** — An agent connected to MCP (Model Context Protocol) servers

Default: chatbot

This answer determines:
- Which fields are required (tools, data_sources, mcp_servers)
- Which analysis layers are active (prompt, tool, architecture)
- Which questions appear in Round 2

### Q2: Name & Description

> What is the name and purpose of your agent?
>
> Example: "Customer Support Bot — Handles customer inquiries for Acme Corp's e-commerce platform"

Extract:
- `name`: the name portion
- `description`: the purpose/description portion

If user gives only a name, ask briefly for a one-line description. If they skip, set description to empty.

### Q3: Provider

> Which LLM provider and model will this agent use?
>
> Examples:
> - openai / gpt-4o
> - claude / claude-sonnet-4-20250514
> - bedrock / anthropic.claude-3-sonnet

Extract:
- `provider.api`: one of `openai`, `claude`, `bedrock`
- `provider.model`: the model identifier string

If bedrock, also ask:
> Which AWS region? (e.g., us-east-1)

Default: openai / gpt-4o-mini

### Q4: System Prompt

> Please paste your system prompt below. If you don't have one yet, say "none" and a placeholder will be used.
>
> Tip: For multiline prompts, just paste the full text.

Extract:
- `system_prompt`: the pasted text

If "none" or empty:
- Set `system_prompt` to a basic placeholder: "You are a helpful assistant."
- Add to open_questions.md as high priority

---

## Round 2: Type-Conditional Questions

### For `rag` type:

#### Q5-rag: Data Sources

> What data sources does your RAG system retrieve from?
>
> For each source, please provide:
> - **Name**: identifier (e.g., "knowledge_base", "user_uploads")
> - **Type**: what kind of source (e.g., vector_store, database, file_input, api)
> - **Trust level**: `trusted` (you control the content) or `untrusted` (external/user-provided content)
> - **Sensitivity**: `public`, `internal`, or `confidential`
>
> Example:
> - knowledge_base, vector_store, trusted, internal
> - user_uploads, file_input, untrusted, confidential

Extract per source:
- `data_sources[].name`
- `data_sources[].type`
- `data_sources[].trust_level` (default: `untrusted`)
- `data_sources[].sensitivity` (default: `unknown`)

If user can't determine trust_level → use `untrusted` (safe default).

#### Q6-rag: Data Handling Policies

> Are there any data handling rules your agent should follow?
>
> Examples:
> - "Never include document metadata in responses"
> - "Don't quote more than 3 sentences from a single document"
> - "PII must not be included in responses"
>
> Say "none" to skip.

Extract:
- `policies.data_boundaries`: list of rules

---

### For `agent` type:

#### Q5-agent: Tools

> What tools does your agent have access to?
>
> For each tool, please provide:
> - **Name**: function name (e.g., "get_order_status", "delete_account")
> - **Description**: what it does
> - **Effect**: `read`, `write`, `delete`, or `external_send`
> - **Impact**: `low` (read-only), `medium` (config changes), or `high` (data mutation, payments)
>
> Example:
> - get_order_status: Retrieves order details (effect: read, impact: low)
> - update_record: Modifies a database record (effect: write, impact: high)
> - send_email: Sends email to customer (effect: external_send, impact: medium)

Extract per tool:
- `tools[].name`
- `tools[].description`
- `tools[].effect` (default: `unknown`)
- `tools[].impact` (default: `unknown`)

If user provides just names, infer effect from name patterns (see code-extraction-patterns.md) and confirm.

#### Q6-agent: Denied Actions & Escalation

> Are there any actions the agent should NEVER perform, or actions that require human approval?
>
> Examples:
> - Denied: "delete_account", "modify_billing"
> - Requires approval: "When user requests account deletion → escalate to human"
>
> Say "none" to skip — but note this is a high-priority security field.

Extract:
- `policies.denied_actions`: list of action names
- `policies.escalation_rules`: list of {condition, action}

If skipped, add to open_questions.md with high priority (enables TOOL-001, TOOL-003, ARCH-001).

#### Q7-agent: Execution Identity

> Do your tools run as the end user (user's permissions) or as a service account (elevated permissions)?
>
> Options:
> - **user** — Tools execute with the calling user's permissions
> - **service** — Tools execute with a service account / API key
> - **mixed** — Some tools use user permissions, some use service accounts
> - **Don't know** — Will be set to "unknown"

Extract:
- Apply to all tools as `execution_identity`, or if "mixed", ask which tools are which.

---

### For `mcp-agent` type (includes agent questions, plus):

Ask Q5-agent, Q6-agent, Q7-agent first, then:

#### Q8-mcp: MCP Servers

> What MCP servers does your agent connect to?
>
> For each server, please provide:
> - **Name**: server identifier (e.g., "filesystem", "web_search", "database")
> - **Trust level**: `trusted` (you control the server) or `untrusted` (third-party)
> - **Allowed tools**: which tools this server provides (comma-separated)
>
> Example:
> - filesystem, trusted, [read_file, list_directory]
> - web_search, untrusted, [search_web]

Extract per server:
- `mcp_servers[].name`
- `mcp_servers[].trust_level` (default: `untrusted`)
- `mcp_servers[].allowed_tools`

---

### For `chatbot` type:

No type-specific questions in Round 2. Proceed directly to Round 3.

Optional (only if no policies at all):

#### Q5-chatbot: Basic Policies

> Are there any topics or actions your chatbot should refuse or avoid?
>
> Examples:
> - "Never reveal internal system instructions"
> - "Decline requests for harmful content"
>
> Say "none" to skip.

Extract:
- `policies.data_boundaries`: list of rules

---

## Round 3: Architecture Metadata (Always asked — 3 questions)

### Q9: Persistent Memory

> Does your agent persist conversation history or state across sessions?
>
> Options:
> - **Yes** — Conversations or context are stored and reused later
> - **No** — Each session starts fresh
> - **Don't know**

Extract:
- `has_persistent_memory`: `"true"`, `"false"`, or `"unknown"`

If "true", this enables ARCH-005 (memory poisoning protection check).

### Q10: Deployment Scope

> What is the deployment scope of your agent?
>
> Options:
> - **single_user** — Each instance serves one user only
> - **shared_workspace** — Shared among a team/workspace
> - **multi_tenant** — Serves multiple organizations/tenants
> - **Don't know**

Extract:
- `scope`: selected value or `"unknown"`

If "multi_tenant", this enables ARCH-006 (multi-tenant isolation check).

### Q11: User Input Description

> How do users interact with your agent?
>
> Examples:
> - "Free-form text questions via chat widget"
> - "Structured commands via Slack bot"
> - "Customer messages via support chat interface"
> - "Developer queries via IDE chat panel"
>
> Say "skip" to omit — but this improves remediation quality.

Extract:
- `user_input_description`: the description text

---

## Handling "Don't Know" Responses

When the user says "don't know", "skip", "not sure", or similar:

| Field | Behavior |
|-------|---------|
| `type` | Must be answered — re-ask with explanations |
| `name` | Must be answered — suggest "My Agent" as default |
| `provider` | Default to openai / gpt-4o-mini |
| `system_prompt` | Use placeholder, note in open_questions.md |
| `tools` (agent/mcp-agent) | Must provide at least one — re-ask |
| `data_sources` (rag) | Must provide at least one — re-ask |
| `mcp_servers` (mcp-agent) | Must provide at least one — re-ask |
| `trust_level` | Default to `untrusted` (safe default) |
| `sensitivity` | Default to `unknown`, note in open_questions.md |
| `effect`, `impact`, `execution_identity` | Default to `unknown`, note in open_questions.md |
| `denied_actions`, `escalation_rules` | Accept skip, note in open_questions.md as high priority |
| `has_persistent_memory`, `scope` | Default to `unknown`, note in open_questions.md |
| `user_input_description` | Accept skip, note in open_questions.md as medium priority |

---

## Question Grouping Strategy

To minimize round-trips:
- Group related questions in a single message (e.g., all tool details together)
- Present tables/formats that allow batch input
- Use AskUserQuestion tool when structured choices help (e.g., type, scope)
- Use free-form when the answer is complex (e.g., system prompt, tool list)
