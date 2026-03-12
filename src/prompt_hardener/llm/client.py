import time
from typing import Dict, Optional

from prompt_hardener.llm.exceptions import (
    LLMConfigurationError,
    LLMProviderError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
)
from prompt_hardener.llm.providers.anthropic_client import AnthropicProvider
from prompt_hardener.llm.providers.bedrock_client import BedrockProvider
from prompt_hardener.llm.providers.openai_client import OpenAIProvider
from prompt_hardener.llm.types import (
    LLMMessage,
    LLMRequest,
    LLMResponse,
    LLMResponseFormat,
)
from prompt_hardener.utils import extract_json_block


class LLMClient:
    def __init__(
        self,
        adapters: Optional[Dict[str, object]] = None,
        max_retries: int = 2,
        default_timeout_seconds: int = 60,
    ):
        self.adapters = adapters or {
            "openai": OpenAIProvider(),
            "claude": AnthropicProvider(),
            "bedrock": BedrockProvider(),
        }
        self.max_retries = max_retries
        self.default_timeout_seconds = default_timeout_seconds

    def generate(self, request: LLMRequest) -> LLMResponse:
        if request.provider not in self.adapters:
            raise LLMConfigurationError(
                "Unsupported LLM provider '%s'" % request.provider
            )

        normalized_request = self._normalize_request(request)
        adapter = self.adapters[normalized_request.provider]
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                return adapter.generate(normalized_request)
            except Exception as exc:
                mapped = self._map_error(exc, normalized_request)
                last_error = mapped
                if attempt >= self.max_retries or not self._is_retryable(mapped):
                    raise mapped
                time.sleep(0.1 * (attempt + 1))
        raise last_error

    def generate_json(self, request: LLMRequest) -> LLMResponse:
        json_request = self._normalize_request(request)
        json_request.response_format = LLMResponseFormat.JSON
        response = self.generate(json_request)
        try:
            response.structured = extract_json_block(response.text)
            return response
        except ValueError as exc:
            raise LLMResponseFormatError(
                "Failed to parse JSON response from %s model '%s': %s"
                % (json_request.provider, json_request.model, exc)
            )

    def _normalize_request(self, request: LLMRequest) -> LLMRequest:
        if request.provider in ("claude", "bedrock"):
            request = self._normalize_system_messages(request)
        if request.timeout_seconds is None:
            request.timeout_seconds = self.default_timeout_seconds
        if request.response_format is None:
            request.response_format = LLMResponseFormat.TEXT
        return request

    def _normalize_system_messages(self, request: LLMRequest) -> LLMRequest:
        system_parts = []
        if request.system_prompt:
            system_parts.append(request.system_prompt)

        normalized_messages = []
        for message in request.messages or []:
            if message.role != "system":
                normalized_messages.append(message)
                continue
            if not isinstance(message.content, str):
                raise LLMConfigurationError(
                    "Provider '%s' requires system messages to have string content"
                    % request.provider
                )
            if message.content:
                system_parts.append(message.content)

        request.messages = [
            LLMMessage(
                role=message.role,
                content=message.content,
                tool_calls=message.tool_calls,
                tool_call_id=message.tool_call_id,
                name=message.name,
            )
            for message in normalized_messages
        ]
        request.system_prompt = "\n\n".join(system_parts) or None
        return request

    def _map_error(self, exc: Exception, request: LLMRequest):
        name = exc.__class__.__name__.lower()
        message = str(exc)
        lower = message.lower()
        prefix = "LLM request failed for provider '%s' model '%s'" % (
            request.provider,
            request.model,
        )
        if isinstance(exc, (LLMTimeoutError, LLMRateLimitError, LLMProviderError)):
            return exc
        if "timeout" in name or "timed out" in lower:
            return LLMTimeoutError("%s: %s" % (prefix, message))
        if "ratelimit" in name or "rate limit" in lower or "429" in lower:
            return LLMRateLimitError("%s: %s" % (prefix, message))
        if "authentication" in name or "api key" in lower:
            return LLMConfigurationError("%s: %s" % (prefix, message))
        return LLMProviderError("%s: %s" % (prefix, message))

    def _is_retryable(self, exc: Exception) -> bool:
        return isinstance(exc, (LLMTimeoutError, LLMRateLimitError, LLMProviderError))
