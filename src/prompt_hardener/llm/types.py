from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class LLMResponseFormat:
    TEXT = "text"
    JSON = "json"


@dataclass
class LLMMessage:
    role: str
    content: Any
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


@dataclass
class LLMUsage:
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None


@dataclass
class LLMRequest:
    provider: str
    model: str
    messages: List[LLMMessage]
    system_prompt: Optional[str] = None
    temperature: Optional[float] = None
    max_output_tokens: Optional[int] = None
    response_format: Optional[str] = None
    timeout_seconds: Optional[int] = None
    stop: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    tools: Optional[List[dict]] = None
    tool_choice: Optional[str] = None
    aws_region: Optional[str] = None
    aws_profile: Optional[str] = None


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    finish_reason: Optional[str] = None
    usage: Optional[LLMUsage] = None
    raw: Any = None
    structured: Any = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    warnings: List[str] = field(default_factory=list)
