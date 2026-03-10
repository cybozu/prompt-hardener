# Code Extraction Patterns

Patterns for extracting agent spec fields from Python codebases (from-code mode).

Each section specifies: target fields, Glob patterns for file discovery, Grep patterns for content matching, and extraction logic.

---

## Step 1: README — name, description, type hints

**Glob patterns:**
```
README.md
README.rst
README.txt
docs/README.md
```

**Extraction logic:**
- First `# heading` → candidate for `name`
- First paragraph or description section → candidate for `description`
- Look for keywords: "chatbot", "RAG", "agent", "MCP", "tool-calling" → hint for `type`
- Confidence: low (READMEs may describe the repo, not the agent)

---

## Step 2: LLM SDK / Provider

**Glob patterns:**
```
**/*.py
requirements.txt
pyproject.toml
setup.py
setup.cfg
Pipfile
```

**Grep patterns for provider detection:**

| Provider | Grep Pattern | Confidence |
|----------|-------------|-----------|
| openai | `from openai\b`, `import openai`, `OpenAI\(` | high |
| openai (key) | `OPENAI_API_KEY` | medium |
| claude | `from anthropic\b`, `import anthropic`, `Anthropic\(` | high |
| claude (key) | `ANTHROPIC_API_KEY` | medium |
| bedrock | `boto3.*bedrock`, `bedrock-runtime`, `BedrockRuntime` | high |
| bedrock (key) | `AWS_PROFILE.*bedrock` | medium |

**Grep patterns for model detection:**
```
model\s*=\s*["']([^"']+)["']
model_id\s*=\s*["']([^"']+)["']
model_name\s*=\s*["']([^"']+)["']
ENGINE\s*=\s*["']([^"']+)["']
```

Known model prefixes: `gpt-`, `claude-`, `anthropic.claude`, `amazon.titan`, `o1-`, `o3-`

**Extraction logic:**
- Match import → set `provider.api`
- Match model string → set `provider.model`
- If bedrock, look for region: `region_name\s*=\s*["']([^"']+)["']`
- Confidence: high for imports, medium for env var references

---

## Step 3: System Prompt

**Glob patterns:**
```
**/*.py
**/prompts/**
**/prompt*.*
**/system_prompt*.*
**/instructions*.*
```

**Grep patterns:**

| Pattern | Description | Confidence |
|---------|-------------|-----------|
| `role.*system` | OpenAI-style system message | high |
| `system_prompt\s*=` | Variable assignment | high |
| `SYSTEM_PROMPT\s*=` | Constant assignment | high |
| `system_instruction\s*=` | Gemini-style | high |
| `SystemMessage\(` | LangChain SystemMessage | high |
| `ChatPromptTemplate.*system` | LangChain template | medium |
| `system\s*=\s*["']{3}\|["']` | Triple-quoted or single-quoted multiline | high |
| `\.system\(` | Builder pattern | medium |
| `messages\s*=.*\{.*role.*system` | Inline message array | medium |

**Extraction logic:**
1. Search for system prompt patterns
2. If found in Python string literal → extract the string value
3. If found as file reference (e.g., `open("prompts/system.txt")`) → read that file
4. If found in a prompts/ directory → read .txt/.md files there
5. Always present extracted prompt to user for confirmation
6. Confidence: high for direct string literals, medium for file references

**Warning:** If the extracted text looks like it contains secrets (long hex/base64 strings, API keys), flag it to the user.

---

## Step 4: Agent Type Determination

**Detection priority (most specific first):**

| Type | Detection Pattern | Grep/Glob | Confidence |
|------|------------------|-----------|-----------|
| mcp-agent | MCP configuration found | `mcp.json`, `MCPServer`, `@modelcontextprotocol`, `mcp_servers` | high |
| agent | Tool/function definitions found | `tools=`, `functions=`, `@tool`, `function_call`, `tool_choice` | high |
| rag | Vector store or retrieval setup | `vectorstore`, `retriever`, `chromadb`, `pinecone`, `faiss`, `RAGChain`, `RetrievalQA` | high |
| chatbot | None of the above | (default) | medium |

**Ambiguity resolution:**
- If both MCP and tools are found → `mcp-agent`
- If both RAG and tools are found → `agent` (agent can have data_sources too)
- Default to more complex type when ambiguous (safer: more rules apply)

---

## Step 5: Tool Definitions

**Glob patterns:**
```
**/*.py
**/openapi.yaml
**/openapi.json
**/swagger.yaml
**/swagger.json
```

**Grep patterns:**

| Framework | Pattern | Confidence |
|-----------|---------|-----------|
| OpenAI functions | `functions\s*=\s*\[`, `tools\s*=\s*\[` | high |
| OpenAI decorator | `@tool` | high |
| LangChain | `Tool\(`, `StructuredTool`, `@tool` | high |
| CrewAI | `@tool` | high |
| Function schemas | `"type":\s*"function"` | high |
| FastAPI endpoints | `@app\.(get\|post\|put\|delete\|patch)` | medium |
| Generic | `def\s+\w+.*->.*:` with docstrings | low |

**Extraction logic for each tool:**
- `name`: function/tool name
- `description`: docstring or description field
- `parameters`: from JSON schema, type hints, or function signature
- `effect`: inferred (see Effect Inference Rules below)
- `impact`: inferred (see Impact Inference Rules below)
- `execution_identity`: inferred (see Identity Inference Rules below)

---

## Step 6: Data Sources

**Glob patterns:**
```
**/*.py
**/docker-compose*.yaml
**/.env.example
**/config*.py
**/settings*.py
```

**Grep patterns:**

| Source Type | Pattern | Inferred `type` |
|-----------|---------|-----------------|
| Vector store | `Chroma`, `Pinecone`, `FAISS`, `Weaviate`, `Milvus`, `Qdrant`, `vectorstore` | `vector_store` |
| Database | `psycopg`, `pymysql`, `sqlalchemy`, `DATABASE_URL`, `mongodb`, `pymongo` | `database` |
| File input | `file_upload`, `UploadFile`, `multipart`, `user.*upload` | `file_input` |
| API client | `requests\.get`, `httpx`, `aiohttp`, `external.*api`, `API_URL` | `api` |
| S3/Cloud | `boto3.*s3`, `google.cloud.storage`, `azure.storage` | `cloud_storage` |

**trust_level inference:**
- User-uploaded files → `untrusted`
- External APIs → `untrusted`
- Internal DB (same infra) → `trusted`
- Cannot determine → `untrusted` (safe default)

**sensitivity inference:**
- PII keywords (email, phone, address, SSN, credit_card) → `confidential`
- Internal docs, employee data → `internal`
- Public content, search results → `public`
- Cannot determine → `unknown`

---

## Step 7: MCP Servers

**Glob patterns:**
```
mcp.json
**/mcp.json
.mcp.json
claude_desktop_config.json
**/mcp_config*.*
```

**Grep patterns:**
```
MCPServer
MCPClient
@modelcontextprotocol
mcp_servers
StdioServerParameters
SSEServerParameters
```

**Extraction logic:**
- Parse `mcp.json` structure for server names and configurations
- Map server capabilities to `allowed_tools`
- trust_level: external/third-party servers → `untrusted`, local/internal → `trusted`
- Confidence: high for mcp.json, medium for code references

---

## Step 8: Policies

**Glob patterns:**
```
**/*.py
**/config*.py
**/settings*.py
**/middleware*.py
**/auth*.py
**/permissions*.py
**/guards*.py
```

**Grep patterns:**

| Policy Field | Pattern | Confidence |
|-------------|---------|-----------|
| denied_actions | `deny`, `forbidden`, `not_allowed`, `blacklist`, `blocklist`, `DENIED_ACTIONS` | medium |
| allowed_actions | `allow`, `whitelist`, `allowlist`, `ALLOWED_ACTIONS`, `permitted` | medium |
| escalation_rules | `escalat`, `human_review`, `approval_required`, `confirm`, `require_confirmation` | medium |
| data_boundaries | `data_boundary`, `pii`, `gdpr`, `data_classification`, `sensitivity` | medium |

**Extraction logic:**
- Look for explicit lists of denied/allowed operations
- Look for confirmation/approval flows → map to escalation_rules
- Look for data handling policies → map to data_boundaries
- Confidence: medium (policies are often implicit in code logic)

---

## Step 9: Memory & Scope

**Grep patterns for memory:**

| Pattern | Inferred Value | Confidence |
|---------|---------------|-----------|
| `redis`, `memcached`, `session_store` | `has_persistent_memory: "true"` | medium |
| `conversation_history`, `chat_history`, `memory=` | `has_persistent_memory: "true"` | medium |
| `ConversationBufferMemory`, `ChatMessageHistory` | `has_persistent_memory: "true"` | high |
| `persistent`, `persist`, `save_context` | `has_persistent_memory: "true"` | medium |

**Grep patterns for scope:**

| Pattern | Inferred Value | Confidence |
|---------|---------------|-----------|
| `tenant_id`, `org_id`, `organization_id`, `multi_tenant` | `scope: "multi_tenant"` | high |
| `workspace_id`, `team_id`, `shared` | `scope: "shared_workspace"` | medium |
| `user_id` (only) with no tenant/org patterns | `scope: "single_user"` | low |

---

## Step 10: Few-shot Messages

**Grep patterns:**
```
messages\s*=\s*\[
example_messages
few_shot
sample_conversation
test_messages
```

**Glob patterns:**
```
**/fixtures/*.json
**/examples/*.json
**/test_data/*.*
```

**Extraction logic:**
- Look for message arrays with role/content structure
- Filter to user/assistant pairs (exclude system messages)
- Confidence: medium (may be test data, not production examples)

---

## Effect Inference Rules

Based on tool name and code analysis:

| Name Pattern | Inferred Effect | Confidence |
|-------------|----------------|-----------|
| `delete_`, `remove_`, `destroy_`, `drop_` | `delete` | medium |
| `write_`, `update_`, `create_`, `modify_`, `insert_`, `set_`, `put_`, `add_`, `edit_`, `save_` | `write` | medium |
| `send_`, `email_`, `notify_`, `post_` (external), `publish_`, `broadcast_`, `alert_` | `external_send` | medium |
| `get_`, `read_`, `fetch_`, `search_`, `list_`, `query_`, `find_`, `check_`, `view_`, `show_`, `retrieve_` | `read` | medium |
| None of the above | `unknown` | low |

**Additional signals from code:**
- HTTP method: DELETE → `delete`, POST/PUT/PATCH → `write`, GET → `read`
- DB operations: `INSERT/UPDATE` → `write`, `DELETE` → `delete`, `SELECT` → `read`
- External service calls: SMTP, webhook, notification API → `external_send`

---

## Impact Inference Rules

| Signal | Inferred Impact | Confidence |
|--------|----------------|-----------|
| DB mutation (INSERT/UPDATE/DELETE on main tables) | `high` | medium |
| Account operations (create/delete/modify user/account) | `high` | medium |
| Payment/billing operations | `high` | high |
| File write/delete operations | `medium` | medium |
| Configuration changes | `medium` | medium |
| Read-only, search, list operations | `low` | medium |
| Cannot determine | `unknown` | low |

---

## Execution Identity Inference Rules

| Signal | Inferred Identity | Confidence |
|--------|------------------|-----------|
| Uses request.user, current_user, user context | `user` | medium |
| Uses service account, API key, admin credentials | `service` | medium |
| Both user context and service credentials present | `mixed` | medium |
| Cannot determine | `unknown` | low |
