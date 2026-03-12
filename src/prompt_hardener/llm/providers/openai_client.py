from typing import Any, Dict, List, Optional

from openai import OpenAI

from prompt_hardener.llm.types import LLMRequest, LLMResponse, LLMUsage

_OPENAI_CLIENT = None


def get_client():
    global _OPENAI_CLIENT
    if _OPENAI_CLIENT is None:
        _OPENAI_CLIENT = OpenAI()
    return _OPENAI_CLIENT


class OpenAIProvider:
    name = "openai"

    def _normalize_tool_calls(self, tool_calls: Any) -> Optional[List[Dict[str, Any]]]:
        normalized = []
        for tool_call in tool_calls or []:
            if hasattr(tool_call, "model_dump"):
                normalized.append(tool_call.model_dump())
                continue
            if hasattr(tool_call, "to_dict"):
                normalized.append(tool_call.to_dict())
                continue
            if isinstance(tool_call, dict):
                normalized.append(tool_call)
                continue
            function = getattr(tool_call, "function", None)
            function_payload = None
            if function is not None:
                if hasattr(function, "model_dump"):
                    function_payload = function.model_dump()
                elif hasattr(function, "to_dict"):
                    function_payload = function.to_dict()
                else:
                    function_payload = {
                        "name": getattr(function, "name", None),
                        "arguments": getattr(function, "arguments", None),
                    }
            normalized.append(
                {
                    "id": getattr(tool_call, "id", None),
                    "type": getattr(tool_call, "type", None),
                    "function": function_payload,
                }
            )
        return normalized or None

    def generate(self, request: LLMRequest) -> LLMResponse:
        kwargs: Dict[str, Any] = {
            "model": request.model,
            "messages": [],
        }
        for message in request.messages:
            payload = {"role": message.role, "content": message.content}
            if message.tool_calls is not None:
                payload["tool_calls"] = message.tool_calls
            if message.tool_call_id is not None:
                payload["tool_call_id"] = message.tool_call_id
            if message.name is not None:
                payload["name"] = message.name
            kwargs["messages"].append(payload)
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature
        if request.max_output_tokens is not None:
            kwargs["max_tokens"] = request.max_output_tokens
        if request.response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}
        if request.stop:
            kwargs["stop"] = request.stop
        if request.tools:
            kwargs["tools"] = request.tools
        if request.tool_choice:
            kwargs["tool_choice"] = request.tool_choice
        if request.timeout_seconds is not None:
            kwargs["timeout"] = request.timeout_seconds

        response = get_client().chat.completions.create(**kwargs)
        choice = response.choices[0] if response.choices else None
        message = choice.message if choice is not None else None
        text = message.content if message and message.content is not None else ""
        tool_calls = (
            self._normalize_tool_calls(getattr(message, "tool_calls", None))
            if message is not None
            else None
        )
        usage = None
        if getattr(response, "usage", None) is not None:
            usage = LLMUsage(
                input_tokens=getattr(response.usage, "prompt_tokens", None),
                output_tokens=getattr(response.usage, "completion_tokens", None),
                total_tokens=getattr(response.usage, "total_tokens", None),
            )
        return LLMResponse(
            text=text,
            provider=self.name,
            model=request.model,
            finish_reason=getattr(choice, "finish_reason", None) if choice else None,
            usage=usage,
            raw=response,
            tool_calls=tool_calls,
        )
