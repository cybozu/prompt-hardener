# Code Extraction Patterns

Patterns for extracting `agent_spec.yaml` fields from Python-centric codebases in `from-code` mode.

Each section lists target fields, discovery patterns, and extraction guidance.

---

## Step 1: README / Docs

**Glob patterns**
```text
README.md
README.rst
README.txt
docs/README.md
docs/**/*.md
```

**Extraction logic**

- First project heading -> candidate for `name`
- First summary paragraph -> candidate for `description`
- Keywords such as `chatbot`, `RAG`, `tool-calling`, `MCP`, `assistant` -> hint for `type`
- Confidence is low unless corroborated by code/config

---

## Step 2: Provider

**Glob patterns**
```text
**/*.py
requirements.txt
pyproject.toml
setup.py
setup.cfg
Pipfile
```

**Provider detection**

| Provider | Grep Pattern | Confidence |
|----------|--------------|------------|
| openai | `from openai\b`, `import openai`, `OpenAI\(` | high |
| claude | `from anthropic\b`, `import anthropic`, `Anthropic\(` | high |
| bedrock | `boto3.*bedrock`, `bedrock-runtime`, `BedrockRuntime` | high |

**Model / region / profile detection**
```text
model\s*=\s*["']([^"']+)["']
model_id\s*=\s*["']([^"']+)["']
model_name\s*=\s*["']([^"']+)["']
ENGINE\s*=\s*["']([^"']+)["']
region_name\s*=\s*["']([^"']+)["']
AWS_PROFILE
profile_name\s*=\s*["']([^"']+)["']
```

**Extraction logic**

- Prefer explicit client construction or config literals
- Record Bedrock `region` / `profile` only if actually configured

---

## Step 3: System Prompt

**Glob patterns**
```text
**/*.py
**/prompts/**
**/prompt*.*
**/system_prompt*.*
**/instructions*.*
```

**Grep patterns**

| Pattern | Description | Confidence |
|---------|-------------|------------|
| `role.*system` | message-array system prompt | high |
| `system_prompt\s*=` | variable assignment | high |
| `SYSTEM_PROMPT\s*=` | constant assignment | high |
| `system_instruction\s*=` | config-style assignment | high |
| `SystemMessage\(` | LangChain-style prompt | high |
| `ChatPromptTemplate.*system` | template-based prompt | medium |
| `open\(.*prompt` | prompt loaded from file | medium |

**Extraction logic**

1. Extract literal strings when directly present
2. Follow file references when prompt text is loaded from disk
3. Record prompt source path in `evidence.md`
4. Warn on secret-like or internal-only content

---

## Step 4: Agent Type

**Detection priority**

| Type | Signals | Confidence |
|------|---------|------------|
| `mcp-agent` | `mcp.json`, MCP server/client code, `@modelcontextprotocol` | high |
| `agent` | tool definitions, function calling, action execution | high |
| `rag` | retrievers, vector stores, document loaders, indexed corpora | high |
| `chatbot` | none of the above | medium |

If tools and retrieval both exist, prefer `agent`. If MCP exists, prefer `mcp-agent`.

---

## Step 5: Tools

**Glob patterns**
```text
**/*.py
**/openapi.yaml
**/openapi.json
**/swagger.yaml
**/swagger.json
```

**Discovery patterns**

| Signal | Pattern | Confidence |
|--------|---------|------------|
| decorator-based tools | `@tool` | high |
| OpenAI-style tool array | `tools\s*=\s*\[`, `functions\s*=\s*\[` | high |
| LangChain/CrewAI | `Tool\(`, `StructuredTool`, `@tool` | high |
| function schema | `"type":\s*"function"` | high |
| generic endpoints | `@app\.(get|post|put|delete|patch)` | medium |

**Extract for each tool**

- `name`
- `description`
- `parameters`
- `effect`
- `impact`
- `execution_identity`
- `source`
- `version`
- `content_hash`

**Provenance hints**

| Signal | Inference |
|--------|-----------|
| tool implemented in local source tree | `source: local` |
| tool bridged through MCP | `source: mcp` |
| SaaS SDK, plugin registry, remote descriptor, vendor package | `source: third_party` |
| unclear ownership | `source: unknown` |

Look for:

```text
version=
__version__
requirements.txt
poetry.lock
uv.lock
package version pins in config
sha256:
content_hash
checksum
digest
```

**Dangerous parameter review for TOOL-007**

Flag parameter schemas or signatures involving names such as:

```text
command
cmd
sql
query
path
file_path
url
recipient
headers
body
payload
```

Treat a parameter as constrained when you find evidence of:

- `enum`
- `const`
- `pattern`
- `format`
- `maxLength`
- `additionalProperties: false`
- strongly typed non-string inputs

If only unconstrained strings or generic objects are exposed, record a TOOL-007 follow-up.

**Ambiguous name review for TOOL-008**

Flag:

- duplicate names
- names repeated in MCP `allowed_tools`
- overly generic names such as `run`, `get`, `call`, `exec`, `tool`

---

## Step 6: Data Sources

**Glob patterns**
```text
**/*.py
**/docker-compose*.yaml
**/.env.example
**/config*.py
**/settings*.py
```

**Detection patterns**

| Source Type | Pattern | Inferred `type` |
|-------------|---------|-----------------|
| vector store | `Chroma`, `Pinecone`, `FAISS`, `Weaviate`, `Milvus`, `Qdrant`, `vectorstore`, `retriever` | `vector_store` |
| database | `psycopg`, `sqlalchemy`, `DATABASE_URL`, `mongodb`, `pymongo` | `database` |
| file input | `UploadFile`, `multipart`, `file_upload`, `user.*upload` | `file_input` |
| API | `requests\.`, `httpx`, `aiohttp`, `API_URL`, `external.*api` | `api` |
| cloud storage | `boto3.*s3`, `google.cloud.storage`, `azure.storage` | `cloud_storage` |

**Trust-level inference**

- user-uploaded or internet-derived content -> `untrusted`
- external third-party API responses -> `untrusted`
- internal curated store under the same control boundary -> `trusted`
- unresolved -> `untrusted`

**Sensitivity inference**

- PII, auth, finance, credentials, secrets -> `confidential`
- internal docs, employee data, ticket history -> `internal`
- public knowledge or internet search -> `public`
- unresolved -> `unknown`

---

## Step 7: MCP Servers

**Glob patterns**
```text
mcp.json
**/mcp.json
.mcp.json
claude_desktop_config.json
**/mcp_config*.*
```

**Discovery patterns**
```text
MCPServer
MCPClient
@modelcontextprotocol
StdioServerParameters
SSEServerParameters
allowed_tools
data_access
```

**Extraction logic**

- Parse config files first when available
- Collect `name`, `trust_level`, `allowed_tools`, `data_access`, `source`, `version`, `content_hash`
- Infer `source: first_party` when the server command/path is repo-local or clearly internal
- Infer `source: third_party` when the server is vendor-hosted, package-managed, or remote
- Use `source: unknown` when ownership is unclear
- If server trust is unclear, default `trust_level` to `untrusted`

---

## Step 8: Policies

**Glob patterns**
```text
**/*.py
**/config*.py
**/settings*.py
**/middleware*.py
**/auth*.py
**/permissions*.py
**/guards*.py
```

**Detection patterns**

| Policy Field | Pattern |
|-------------|---------|
| `allowed_actions` | `allowlist`, `whitelist`, `allowed_actions`, `permitted` |
| `denied_actions` | `deny`, `forbidden`, `blocklist`, `denied_actions`, `not_allowed` |
| `escalation_rules` | `escalat`, `approval_required`, `human_review`, `confirm`, `require_confirmation` |
| `data_boundaries` | `data_boundary`, `pii`, `gdpr`, `classification`, `confidential`, `internal` |
| budget ceilings | `max_tool_calls`, `max_steps`, `rate_limit`, `throttle`, `cost_budget`, `budget`, `quota` |

**Extraction logic**

- Prefer explicit config structures
- Map confirm/approval gates to `escalation_rules`
- Map execution ceilings to `max_tool_calls`, `max_steps`, `rate_limits`, `cost_budget`
- If only prompt-language ceilings exist, record them in `evidence.md` and note lower confidence

---

## Step 9: Memory, Scope, And Isolation

**Persistent memory signals**

| Pattern | Inference |
|---------|-----------|
| `redis`, `memcached`, `session_store`, `save_context`, `persist` | `has_persistent_memory: "true"` |
| `ConversationBufferMemory`, `ChatMessageHistory` | `has_persistent_memory: "true"` |

**Memory protection signals**
```text
ttl
expiry
expiration
rollback
quarantine
validate before storing
store provenance
write filter
memory poisoning
session segmentation
```

**Scope signals**

| Pattern | Inference |
|---------|-----------|
| `tenant_id`, `org_id`, `organization_id`, `multi_tenant` | `scope: "multi_tenant"` |
| `workspace_id`, `team_id`, `shared` | `scope: "shared_workspace"` |
| only `user_id` or clearly per-user storage | `scope: "single_user"` |

**Tenant-isolation signals**
```text
per-tenant
per-user
tenant namespace
user-scoped
session segmentation
namespace per tenant
tenant isolation
```

If memory exists but protection evidence is absent, record an ARCH-005 follow-up.
If multi-tenant scope exists with memory or sensitive data but isolation evidence is absent, record an ARCH-007 follow-up.

---

## Step 10: Few-Shot Messages

**Grep patterns**
```text
messages\s*=\s*\[
example_messages
few_shot
sample_conversation
test_messages
```

**Glob patterns**
```text
**/fixtures/*.json
**/examples/*.json
**/test_data/*.*
```

**Extraction logic**

- Keep only user/assistant examples
- Exclude system messages
- Treat tests and fixtures as medium-to-low confidence unless confirmed

---

## Effect Inference Rules

| Signal | Effect | Confidence |
|--------|--------|------------|
| `delete_`, `remove_`, `destroy_`, `drop_` | `delete` | medium |
| `write_`, `update_`, `create_`, `modify_`, `insert_`, `set_`, `put_`, `save_` | `write` | medium |
| `send_`, `email_`, `notify_`, `webhook_`, `publish_`, `broadcast_`, `upload_` | `external_send` | medium |
| `get_`, `read_`, `fetch_`, `search_`, `list_`, `find_`, `retrieve_` | `read` | medium |
| explicit HTTP verb / SQL verb evidence | map by verb semantics | high |
| unresolved | `unknown` | low |

## Impact Inference Rules

| Signal | Impact | Confidence |
|--------|--------|------------|
| payments, billing, account lifecycle, privileged mutations | `high` | high |
| DB mutation on primary records, irreversible external actions | `high` | medium |
| file/config mutation without major blast radius | `medium` | medium |
| read-only/search/list | `low` | medium |
| unresolved | `unknown` | low |

## Execution Identity Inference Rules

| Signal | Identity | Confidence |
|--------|----------|------------|
| request-scoped user token, delegated auth | `user` | medium |
| service account, static API key, backend credential | `service` | medium |
| mixture of both depending on tool | `mixed` | medium |
| unresolved | `unknown` | low |
