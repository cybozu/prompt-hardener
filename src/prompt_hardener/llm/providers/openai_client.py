from typing import Any, Dict

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

    def generate(self, request: LLMRequest) -> LLMResponse:
        kwargs: Dict[str, Any] = {
            "model": request.model,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
        }
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
        )
