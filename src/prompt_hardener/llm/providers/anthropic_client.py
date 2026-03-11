from typing import Any, Dict

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
            kwargs["tools"] = request.tools
        if request.timeout_seconds is not None:
            kwargs["timeout"] = request.timeout_seconds

        response = get_client().messages.create(**kwargs)
        text_parts = []
        for block in getattr(response, "content", []) or []:
            if getattr(block, "type", None) == "text":
                text_parts.append(getattr(block, "text", ""))
            elif hasattr(block, "text"):
                text_parts.append(getattr(block, "text", ""))
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
        )
