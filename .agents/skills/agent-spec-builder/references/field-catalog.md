# Field Catalog

Reference of current `agent_spec.yaml` fields, their analysis value, and the rules they enable.

## Legend

- **Analysis Value**
  - `critical` — enables critical-severity findings directly
  - `high` — enables or sharpens high-severity findings
  - `medium` — enables medium-severity findings or materially improves analysis quality
  - `low` — mostly contextual or remediation-oriented
- **Applicable Types**
  - `all` = chatbot, rag, agent, mcp-agent

---

## Root Fields

| Field Path | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules / Purpose |
|-----------|----------|------------------|----------------|----------------|-------------------------|
| `version` | yes | all | `"1.0"` | — | Schema validation only |
| `type` | yes | all | `chatbot`, `rag`, `agent`, `mcp-agent` | high | Determines active layers and conditional required fields |
| `name` | yes | all | free text | — | Display only |
| `description` | no | all | free text | low | Improves context and remediation quality |
| `system_prompt` | yes | all | free text | critical | PROMPT-001, PROMPT-002, PROMPT-003, ARCH-002, ARCH-004, ARCH-006 evidence |
| `user_input_description` | no | all | free text | medium | Improves remediation quality |
| `has_persistent_memory` | no | all | `true`, `false`, `unknown` | high | ARCH-004, ARCH-006 |
| `scope` | no | all | `single_user`, `shared_workspace`, `multi_tenant`, `unknown` | high | ARCH-005, ARCH-006 |

## Provider

| Field Path | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules / Purpose |
|-----------|----------|------------------|----------------|----------------|-------------------------|
| `provider.api` | yes | all | `openai`, `claude`, `bedrock` | — | Config only |
| `provider.model` | yes | all | model identifier string | — | Config only |
| `provider.region` | no | bedrock | AWS region string | — | Config only |
| `provider.profile` | no | bedrock | AWS profile string | — | Config only |

## Messages

| Field Path | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules / Purpose |
|-----------|----------|------------------|----------------|----------------|-------------------------|
| `messages` | no | all | array of `{role, content}` | low | Analysis context |
| `messages[].role` | yes per item | all | `user`, `assistant` | — | Schema only |
| `messages[].content` | yes per item | all | free text | — | Schema only |

## Tools

| Field Path | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules / Purpose |
|-----------|----------|------------------|----------------|----------------|-------------------------|
| `tools` | yes for `agent`, `mcp-agent` | agent, mcp-agent | array | high | Activates tool and architecture analysis |
| `tools[].name` | yes per item | agent, mcp-agent | function name | high | TOOL-001, TOOL-006, TOOL-007, TOOL-008 |
| `tools[].description` | yes per item | agent, mcp-agent | free text | medium | TOOL-006, TOOL-007, TOOL-008 context |
| `tools[].parameters` | no | agent, mcp-agent | JSON Schema object | high | TOOL-007 |
| `tools[].effect` | no | agent, mcp-agent | `read`, `write`, `delete`, `external_send`, `unknown` | critical | TOOL-001, TOOL-006, ARCH-002 severity |
| `tools[].impact` | no | agent, mcp-agent | `low`, `medium`, `high`, `unknown` | critical | TOOL-003 |
| `tools[].execution_identity` | no | agent, mcp-agent | `user`, `service`, `mixed`, `unknown` | high | TOOL-004 |
| `tools[].source` | no | agent, mcp-agent | `local`, `third_party`, `mcp`, `unknown` | high | ARCH-008, TOOL-008 context |
| `tools[].version` | no | agent, mcp-agent | free text | high | ARCH-008, TOOL-008 context |
| `tools[].content_hash` | no | agent, mcp-agent | free text such as `sha256:...` | high | ARCH-008 |

## Policies

| Field Path | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules / Purpose |
|-----------|----------|------------------|----------------|----------------|-------------------------|
| `policies` | no | all | object | high | Container for multiple controls |
| `policies.allowed_actions` | no | agent, mcp-agent | array of tool names | medium | TOOL-002 |
| `policies.denied_actions` | no | agent, mcp-agent | array of action names | high | TOOL-001, TOOL-003, TOOL-004 |
| `policies.data_boundaries` | no | all | array of natural-language controls | high | TOOL-005, ARCH-004, ARCH-006 evidence |
| `policies.escalation_rules` | no | agent, mcp-agent | array of `{condition, action}` | high | TOOL-001, TOOL-003, TOOL-004 |
| `policies.escalation_rules[].condition` | yes per item | agent, mcp-agent | free text | — | Schema only |
| `policies.escalation_rules[].action` | yes per item | agent, mcp-agent | free text | — | Schema only |
| `policies.max_tool_calls` | no | agent, mcp-agent | integer >= 1 | medium | ARCH-007 |
| `policies.max_steps` | no | agent, mcp-agent | integer >= 1 | medium | ARCH-007 |
| `policies.rate_limits` | no | agent, mcp-agent | array of strings | medium | ARCH-007 |
| `policies.cost_budget` | no | agent, mcp-agent | free text | medium | ARCH-007 |

## Data Sources

| Field Path | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules / Purpose |
|-----------|----------|------------------|----------------|----------------|-------------------------|
| `data_sources` | yes for `rag` | rag, agent, mcp-agent | array | high | PROMPT-001, ARCH-003, TOOL-005, TOOL-006, ARCH-006 |
| `data_sources[].name` | yes per item | rag, agent, mcp-agent | identifier string | medium | TOOL-005 reference |
| `data_sources[].type` | yes per item | rag, agent, mcp-agent | free text such as `vector_store`, `api`, `database` | low | Context only |
| `data_sources[].trust_level` | yes per item | rag, agent, mcp-agent | `trusted`, `untrusted`, `unknown` | high | PROMPT-001, ARCH-003 |
| `data_sources[].description` | no | rag, agent, mcp-agent | free text | low | Context only |
| `data_sources[].sensitivity` | no | rag, agent, mcp-agent | `public`, `internal`, `confidential`, `unknown` | high | TOOL-005, TOOL-006, ARCH-006 |

## MCP Servers

| Field Path | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules / Purpose |
|-----------|----------|------------------|----------------|----------------|-------------------------|
| `mcp_servers` | yes for `mcp-agent` | mcp-agent | array | high | ARCH-001, ARCH-003, ARCH-008, TOOL-008 context |
| `mcp_servers[].name` | yes per item | mcp-agent | identifier string | medium | Display and disambiguation context |
| `mcp_servers[].trust_level` | yes per item | mcp-agent | `trusted`, `untrusted`, `unknown` | high | ARCH-001, ARCH-003 |
| `mcp_servers[].allowed_tools` | no | mcp-agent | array of tool names | high | ARCH-001, TOOL-008 context |
| `mcp_servers[].data_access` | no | mcp-agent | array of source names | medium | Architecture context |
| `mcp_servers[].source` | no | mcp-agent | `first_party`, `third_party`, `unknown` | high | ARCH-008 |
| `mcp_servers[].version` | no | mcp-agent | free text | high | ARCH-008 |
| `mcp_servers[].content_hash` | no | mcp-agent | free text such as `sha256:...` | high | ARCH-008 |

---

## Rules Quick Reference

### Prompt Layer

| Rule ID | Severity | Key Fields |
|---------|----------|-----------|
| `PROMPT-001` | high | `system_prompt`, `data_sources[].trust_level`, `mcp_servers[].trust_level` |
| `PROMPT-002` | high | `system_prompt` |
| `PROMPT-003` | medium | `system_prompt` |

### Tool Layer

| Rule ID | Severity | Key Fields |
|---------|----------|-----------|
| `TOOL-001` | high | `tools[].name`, `tools[].effect`, `policies.denied_actions`, `policies.escalation_rules` |
| `TOOL-002` | medium | `policies.allowed_actions` |
| `TOOL-003` | critical | `tools[].impact`, `policies.denied_actions`, `policies.escalation_rules` |
| `TOOL-004` | high | `tools[].execution_identity`, `policies.denied_actions`, `policies.escalation_rules` |
| `TOOL-005` | high | `data_sources[].sensitivity`, `policies.data_boundaries` |
| `TOOL-006` | critical | `data_sources[].sensitivity`, `tools[].effect`, `tools[].name`, `tools[].description` |
| `TOOL-007` | high | `tools[].parameters`, `tools[].name`, `tools[].description` |
| `TOOL-008` | medium | `tools[].name`, `tools[].source`, `tools[].version`, `mcp_servers[].allowed_tools` |

### Architecture Layer

| Rule ID | Severity | Key Fields |
|---------|----------|-----------|
| `ARCH-001` | high | `mcp_servers[].trust_level`, `mcp_servers[].allowed_tools` |
| `ARCH-002` | medium/high | `system_prompt`, `tools[].effect` |
| `ARCH-003` | medium | `data_sources[].trust_level`, `mcp_servers[].trust_level` |
| `ARCH-004` | high | `has_persistent_memory`, `system_prompt`, `policies.data_boundaries` |
| `ARCH-005` | high | `scope`, `tools`, `tools[].effect` |
| `ARCH-006` | high | `scope`, `has_persistent_memory`, `data_sources[].sensitivity`, `system_prompt`, `policies.data_boundaries` |
| `ARCH-007` | medium | `policies.max_tool_calls`, `policies.max_steps`, `policies.rate_limits`, `policies.cost_budget` |
| `ARCH-008` | high | tool and MCP provenance fields |

---

## Safe Defaults

When a value cannot be established confidently:

| Field | Safe Default | Rationale |
|-------|--------------|-----------|
| `data_sources[].trust_level` | `untrusted` | Bias toward PROMPT-001 protection |
| `mcp_servers[].trust_level` | `untrusted` | Bias toward ARCH-001 restriction |
| `tools[].effect` | `unknown` | Avoid false classification while preserving follow-up |
| `tools[].impact` | `unknown` | Avoid false critical classification while preserving follow-up |
| `tools[].execution_identity` | `unknown` | Preserve TOOL-004 follow-up |
| `tools[].source` | `unknown` | Preserve ARCH-008 follow-up when provenance is unclear |
| `mcp_servers[].source` | `unknown` | Preserve ARCH-008 follow-up when provenance is unclear |
| `data_sources[].sensitivity` | `unknown` | Preserve TOOL-005/006 follow-up |
| `has_persistent_memory` | `unknown` | Preserve ARCH-004/006 follow-up |
| `scope` | `unknown` | Preserve ARCH-005/006 follow-up |

Do not invent `version`, `content_hash`, or budget fields. Leave them unset and record the missing information in `open_questions.md`.
