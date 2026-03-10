# Field Catalog

Complete reference of all `agent_spec.yaml` fields with their analysis value and associated rules.

## Legend

- **Analysis Value**: How much this field contributes to Prompt Hardener analysis
  - `critical` — Enables critical-severity rules
  - `high` — Enables high-severity rules
  - `medium` — Enables medium-severity rules
  - `low` — Informational or improves remediation quality
- **Applicable Types**: Which agent types use this field
  - `all` = chatbot, rag, agent, mcp-agent

---

## Root Fields

| Field Path | Type | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules |
|-----------|------|----------|-----------------|---------------|---------------|--------------|
| `version` | string | yes (all) | all | `"1.0"` (const) | — | Schema validation only |
| `type` | string | yes (all) | all | `chatbot`, `rag`, `agent`, `mcp-agent` | high | Determines active analysis layers and conditional required fields |
| `name` | string | yes (all) | all | free text | — | Display only |
| `description` | string | no | all | free text | low | Improves remediation context |
| `system_prompt` | string | yes (all) | all | free text (YAML block scalar `\|` for multiline) | critical | PROMPT-001, PROMPT-002, PROMPT-003, PROMPT-004, ARCH-003, ARCH-005 |
| `user_input_description` | string | no | all | free text | medium | Improves remediation quality |
| `has_persistent_memory` | string | no | all | `true`, `false`, `unknown` | high | ARCH-005 (memory poisoning protection) |
| `scope` | string | no | all | `single_user`, `shared_workspace`, `multi_tenant`, `unknown` | high | ARCH-006 (multi-tenant isolation) |

## Provider

| Field Path | Type | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules |
|-----------|------|----------|-----------------|---------------|---------------|--------------|
| `provider.api` | string | yes (all) | all | `openai`, `claude`, `bedrock` | — | Config only |
| `provider.model` | string | yes (all) | all | model identifier string | — | Config only |
| `provider.region` | string | no | bedrock only | AWS region string | — | Config only |
| `provider.profile` | string | no | bedrock only | AWS profile name | — | Config only |

## Messages

| Field Path | Type | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules |
|-----------|------|----------|-----------------|---------------|---------------|--------------|
| `messages` | array | no | all | Array of {role, content} | low | Few-shot examples for analysis context |
| `messages[].role` | string | yes (per item) | all | `user`, `assistant` | — | — |
| `messages[].content` | string | yes (per item) | all | free text | — | — |

## Tools

| Field Path | Type | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules |
|-----------|------|----------|-----------------|---------------|---------------|--------------|
| `tools` | array | yes (agent, mcp-agent) | agent, mcp-agent | Array of tool definitions | high | TOOL-001 through TOOL-006, ARCH-001, ARCH-003, ARCH-006 |
| `tools[].name` | string | yes (per item) | agent, mcp-agent | function name | high | Matched against sensitive tool patterns (TOOL-001) |
| `tools[].description` | string | yes (per item) | agent, mcp-agent | free text | medium | Remediation context |
| `tools[].parameters` | object | no | agent, mcp-agent | JSON Schema object | low | Informational |
| `tools[].effect` | string | no | agent, mcp-agent | `read`, `write`, `delete`, `external_send`, `unknown` | **critical** | TOOL-006 (exfiltration risk with confidential data), TOOL-001, ARCH-003 (severity elevation) |
| `tools[].impact` | string | no | agent, mcp-agent | `low`, `medium`, `high`, `unknown` | **critical** | TOOL-003 (high-impact tool escalation check) |
| `tools[].execution_identity` | string | no | agent, mcp-agent | `user`, `service`, `mixed`, `unknown` | high | TOOL-004 (service identity escalation check) |

## Policies

| Field Path | Type | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules |
|-----------|------|----------|-----------------|---------------|---------------|--------------|
| `policies` | object | no | agent, mcp-agent (recommended) | — | high | Multiple TOOL and ARCH rules |
| `policies.allowed_actions` | array[string] | no | agent, mcp-agent | tool name strings | medium | TOOL-002 (allowlist check) |
| `policies.denied_actions` | array[string] | no | agent, mcp-agent | tool/action name strings | high | TOOL-001, TOOL-003, TOOL-004 (deny coverage checks) |
| `policies.data_boundaries` | array[string] | no | all | natural language rules | high | TOOL-005 (confidential data boundary check) |
| `policies.escalation_rules` | array | no | agent, mcp-agent | Array of {condition, action} | high | TOOL-001, TOOL-003, TOOL-004, ARCH-001 |
| `policies.escalation_rules[].condition` | string | yes (per item) | agent, mcp-agent | natural language condition | — | — |
| `policies.escalation_rules[].action` | string | yes (per item) | agent, mcp-agent | natural language action | — | — |

## Data Sources

| Field Path | Type | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules |
|-----------|------|----------|-----------------|---------------|---------------|--------------|
| `data_sources` | array | yes (rag) | rag, agent, mcp-agent | Array of data source definitions | high | PROMPT-001, ARCH-004, TOOL-005, TOOL-006 |
| `data_sources[].name` | string | yes (per item) | rag, agent, mcp-agent | identifier string | medium | Referenced in TOOL-005 boundary checks |
| `data_sources[].type` | string | yes (per item) | rag, agent, mcp-agent | e.g. `vector_store`, `file_input`, `api`, `database` | low | Informational |
| `data_sources[].trust_level` | string | yes (per item) | rag, agent, mcp-agent | `trusted`, `untrusted`, `unknown` | high | PROMPT-001 (boundary markers for untrusted), ARCH-004 (unknown trust flagged) |
| `data_sources[].description` | string | no | rag, agent, mcp-agent | free text | low | Informational |
| `data_sources[].sensitivity` | string | no | rag, agent, mcp-agent | `public`, `internal`, `confidential`, `unknown` | high | TOOL-005 (confidential data boundary), TOOL-006 (exfiltration risk) |

## MCP Servers

| Field Path | Type | Required | Applicable Types | Allowed Values | Analysis Value | Enabled Rules |
|-----------|------|----------|-----------------|---------------|---------------|--------------|
| `mcp_servers` | array | yes (mcp-agent) | mcp-agent | Array of MCP server definitions | high | ARCH-002, ARCH-004 |
| `mcp_servers[].name` | string | yes (per item) | mcp-agent | identifier string | medium | Display/reference |
| `mcp_servers[].trust_level` | string | yes (per item) | mcp-agent | `trusted`, `untrusted`, `unknown` | high | ARCH-002 (untrusted server tool restriction), ARCH-004 (unknown trust flagged) |
| `mcp_servers[].allowed_tools` | array[string] | no | mcp-agent | tool name strings | high | ARCH-002 (empty allowed_tools on untrusted = finding) |
| `mcp_servers[].data_access` | array[string] | no | mcp-agent | data source name strings | medium | Informational |

---

## Rules Quick Reference

### Prompt Layer (chatbot, rag, agent, mcp-agent)

| Rule ID | Severity | Name | Key Fields |
|---------|----------|------|-----------|
| PROMPT-001 | high | Missing instruction-data boundary | `system_prompt`, `data_sources[].trust_level` |
| PROMPT-002 | medium | No secrets protection instruction | `system_prompt` |
| PROMPT-003 | medium | Missing role definition | `system_prompt` |
| PROMPT-004 | high | No untrusted input handling | `system_prompt` |

### Tool Layer (agent, mcp-agent)

| Rule ID | Severity | Name | Key Fields |
|---------|----------|------|-----------|
| TOOL-001 | high | Sensitive tool without deny/escalation coverage | `tools[].name`, `tools[].effect`, `policies.denied_actions`, `policies.escalation_rules` |
| TOOL-002 | medium | No tool allowlist defined | `policies.allowed_actions` |
| TOOL-003 | critical | High-impact tool without escalation | `tools[].impact`, `policies.denied_actions`, `policies.escalation_rules` |
| TOOL-004 | high | Service-identity tool without escalation | `tools[].execution_identity`, `policies.denied_actions`, `policies.escalation_rules` |
| TOOL-005 | high | Confidential data without boundary | `data_sources[].sensitivity`, `policies.data_boundaries` |
| TOOL-006 | critical | Exfiltration risk (confidential + external_send) | `data_sources[].sensitivity`, `tools[].effect` |

### Architecture Layer (rag, agent, mcp-agent)

| Rule ID | Severity | Name | Key Fields |
|---------|----------|------|-----------|
| ARCH-001 | high | Sensitive tools without escalation rules | `tools`, `policies.escalation_rules` |
| ARCH-002 | high | Untrusted MCP server without tool restriction | `mcp_servers[].trust_level`, `mcp_servers[].allowed_tools` |
| ARCH-003 | medium/high | No tool result validation in prompt | `system_prompt`, `tools[].effect` (elevates severity) |
| ARCH-004 | medium | Unknown trust level on data source or MCP server | `data_sources[].trust_level`, `mcp_servers[].trust_level` |
| ARCH-005 | high | Persistent memory without protection | `has_persistent_memory`, `system_prompt` |
| ARCH-006 | high | Multi-tenant scope with sensitive tools | `scope`, `tools` |

---

## Safe Defaults

When a field value cannot be determined:

| Field | Safe Default | Rationale |
|-------|-------------|-----------|
| `trust_level` (data_sources, mcp_servers) | `untrusted` | Triggers protective rules (PROMPT-001, ARCH-002) |
| `effect` | `unknown` | Does not suppress TOOL-001 name-based detection |
| `impact` | `unknown` | Does not trigger TOOL-003 but noted in open_questions |
| `execution_identity` | `unknown` | Does not trigger TOOL-004 but noted in open_questions |
| `sensitivity` | `unknown` | Does not trigger TOOL-005/006 but noted in open_questions |
| `has_persistent_memory` | `unknown` | Does not trigger ARCH-005 but noted in open_questions |
| `scope` | `unknown` | Does not trigger ARCH-006 but noted in open_questions |
