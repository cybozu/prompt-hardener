import json
from typing import Any, Dict, List, Optional

from anthropic import Anthropic

from prompt_hardener.llm.types import LLMRequest, LLMResponse, LLMUsage

_ANTHROPIC_CLIENT = None


def get_client():
    global _ANTHROPIC_CLIENT
    if _ANTHROPIC_CLIENT is None:
        _ANTHROPIC_CLIENT = Anthropic()
    return _ANTHROPIC_CLIENT


class AnthropicProvider:
    name = "claude"

    def _normalize_tools(self, tools: Optional[List[Dict[str, Any]]]):
        normalized = []
        for tool in tools or []:
            if "name" in tool and "input_schema" in tool:
                normalized.append(tool)
                continue
            function = tool.get("function", {}) if isinstance(tool, dict) else {}
            normalized.append(
                {
                    "name": function.get("name"),
                    "description": function.get("description", ""),
                    "input_schema": function.get("parameters")
                    or {"type": "object", "properties": {}},
                }
            )
        return normalized or None

    def _normalize_tool_calls(self, blocks: Any) -> Optional[List[Dict[str, Any]]]:
        normalized = []
        for block in blocks or []:
            block_type = getattr(block, "type", None)
            if block_type != "tool_use":
                continue
            tool_input = getattr(block, "input", None)
            normalized.append(
                {
                    "id": getattr(block, "id", None),
                    "type": "function",
                    "function": {
                        "name": getattr(block, "name", None),
                        "arguments": json.dumps(tool_input, ensure_ascii=False),
                    },
                }
            )
        return normalized or None

    def generate(self, request: LLMRequest) -> LLMResponse:
        kwargs: Dict[str, Any] = {
            "model": request.model,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
        }
        if request.system_prompt is not None:
            kwargs["system"] = request.system_prompt
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature
        if request.max_output_tokens is not None:
            kwargs["max_tokens"] = request.max_output_tokens
        if request.stop:
            kwargs["stop_sequences"] = request.stop
        if request.tools:
            kwargs["tools"] = self._normalize_tools(request.tools)
        if request.timeout_seconds is not None:
            kwargs["timeout"] = request.timeout_seconds

        response = get_client().messages.create(**kwargs)
        text_parts = []
        content_blocks = getattr(response, "content", []) or []
        for block in content_blocks:
            if getattr(block, "type", None) == "text":
                text_parts.append(getattr(block, "text", ""))
            elif hasattr(block, "text"):
                text_parts.append(getattr(block, "text", ""))
        tool_calls = self._normalize_tool_calls(content_blocks)
        usage = None
        if getattr(response, "usage", None) is not None:
            usage = LLMUsage(
                input_tokens=getattr(response.usage, "input_tokens", None),
                output_tokens=getattr(response.usage, "output_tokens", None),
                total_tokens=None,
            )
        return LLMResponse(
            text="".join(text_parts).strip(),
            provider=self.name,
            model=request.model,
            finish_reason=getattr(response, "stop_reason", None),
            usage=usage,
            raw=response,
            tool_calls=tool_calls,
        )
