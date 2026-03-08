from dataclasses import dataclass
from typing import Dict, List, Optional

from prompt_hardener.schema import PromptInput


@dataclass
class SuccessCriteria:
    description: str
    indicators: List[str]


@dataclass
class Scenario:
    id: str
    name: str
    category: str
    target_layer: str
    applicability: List[str]
    injection_method: str
    payloads: List[str]
    success_criteria: SuccessCriteria
    description: Optional[str] = None


@dataclass
class ProviderConfig:
    api: str  # "openai" | "claude" | "bedrock"
    model: str
    region: Optional[str] = None
    profile: Optional[str] = None


@dataclass
class ToolDef:
    name: str
    description: str
    parameters: Optional[Dict] = None


@dataclass
class EscalationRule:
    condition: str
    action: str


@dataclass
class Policies:
    allowed_actions: Optional[List[str]] = None
    denied_actions: Optional[List[str]] = None
    data_boundaries: Optional[List[str]] = None
    escalation_rules: Optional[List[EscalationRule]] = None


@dataclass
class DataSource:
    name: str
    type: str
    trust_level: str  # "trusted" | "untrusted"
    description: Optional[str] = None


@dataclass
class McpServer:
    name: str
    trust_level: str  # "trusted" | "untrusted"
    allowed_tools: Optional[List[str]] = None
    data_access: Optional[List[str]] = None


@dataclass
class AgentSpec:
    version: str
    type: str  # "chatbot" | "rag" | "agent" | "mcp-agent"
    name: str
    system_prompt: str
    provider: ProviderConfig
    description: Optional[str] = None
    messages: Optional[List[Dict[str, str]]] = None
    tools: Optional[List[ToolDef]] = None
    policies: Optional[Policies] = None
    data_sources: Optional[List[DataSource]] = None
    mcp_servers: Optional[List[McpServer]] = None
    user_input_description: Optional[str] = None

    def to_prompt_input(self):
        # type: () -> PromptInput
        api = self.provider.api
        if api == "openai":
            messages = [{"role": "system", "content": self.system_prompt}]
            if self.messages:
                messages.extend(self.messages)
            return PromptInput(
                mode="chat",
                messages=messages,
                messages_format="openai",
            )
        elif api in ("claude", "bedrock"):
            messages = list(self.messages) if self.messages else []
            return PromptInput(
                mode="chat",
                messages=messages,
                messages_format=api,
                system_prompt=self.system_prompt,
            )
        else:
            raise ValueError("Unsupported provider API: %s" % api)
