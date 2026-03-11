import json
from types import SimpleNamespace

import pytest

from prompt_hardener.llm.client import LLMClient
from prompt_hardener.llm.exceptions import (
    LLMConfigurationError,
    LLMResponseFormatError,
    LLMTimeoutError,
)
from prompt_hardener.llm.providers.anthropic_client import AnthropicProvider
from prompt_hardener.llm.providers.bedrock_client import BedrockProvider
from prompt_hardener.llm.providers.openai_client import OpenAIProvider
from prompt_hardener.llm.types import LLMMessage, LLMRequest, LLMResponse, LLMUsage
from prompt_hardener.llm_client import (
    call_llm_api_for_attack_completion,
    call_llm_api_for_eval,
)
from prompt_hardener.schema import PromptInput


class _FakeAdapter:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, request):
        self.calls.append(request)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_client_dispatches_to_selected_provider():
    adapter = _FakeAdapter(
        [
            LLMResponse(
                text="ok",
                provider="openai",
                model="gpt-4o-mini",
                usage=LLMUsage(total_tokens=3),
            )
        ]
    )
    client = LLMClient(adapters={"openai": adapter})
    request = LLMRequest(
        provider="openai",
        model="gpt-4o-mini",
        messages=[LLMMessage(role="user", content="hello")],
    )

    response = client.generate(request)

    assert response.text == "ok"
    assert adapter.calls[0].provider == "openai"
    assert adapter.calls[0].timeout_seconds == 60
    assert adapter.calls[0].response_format == "text"


def test_client_generate_json_parses_structured_response():
    adapter = _FakeAdapter(
        [
            LLMResponse(
                text='{"result": "ok"}',
                provider="claude",
                model="claude-sonnet",
            )
        ]
    )
    client = LLMClient(adapters={"claude": adapter})

    response = client.generate_json(
        LLMRequest(
            provider="claude",
            model="claude-sonnet",
            messages=[LLMMessage(role="user", content="hello")],
        )
    )

    assert response.structured == {"result": "ok"}
    assert adapter.calls[0].response_format == "json"


def test_client_generate_json_raises_normalized_format_error():
    adapter = _FakeAdapter(
        [LLMResponse(text="not json", provider="claude", model="claude-sonnet")]
    )
    client = LLMClient(adapters={"claude": adapter})

    with pytest.raises(LLMResponseFormatError):
        client.generate_json(
            LLMRequest(
                provider="claude",
                model="claude-sonnet",
                messages=[LLMMessage(role="user", content="hello")],
            )
        )


def test_client_retries_timeout_and_succeeds():
    adapter = _FakeAdapter(
        [
            TimeoutError("timed out"),
            LLMResponse(text="ok", provider="openai", model="gpt-4o-mini"),
        ]
    )
    client = LLMClient(adapters={"openai": adapter}, max_retries=1)

    response = client.generate(
        LLMRequest(
            provider="openai",
            model="gpt-4o-mini",
            messages=[LLMMessage(role="user", content="hello")],
        )
    )

    assert response.text == "ok"
    assert len(adapter.calls) == 2


def test_client_raises_configuration_error_for_unknown_provider():
    client = LLMClient(adapters={"openai": _FakeAdapter([])})

    with pytest.raises(LLMConfigurationError):
        client.generate(
            LLMRequest(
                provider="unknown",
                model="m",
                messages=[LLMMessage(role="user", content="hello")],
            )
        )


def test_openai_provider_normalizes_response(monkeypatch):
    captured = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    finish_reason="stop",
                    message=SimpleNamespace(content='{"result":"ok"}'),
                )
            ],
            usage=SimpleNamespace(
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
            ),
        )

    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create))
    )
    monkeypatch.setattr(
        "prompt_hardener.llm.providers.openai_client.get_client",
        lambda: fake_client,
    )

    response = OpenAIProvider().generate(
        LLMRequest(
            provider="openai",
            model="gpt-4o-mini",
            messages=[LLMMessage(role="user", content="hello")],
            response_format="json",
            max_output_tokens=42,
            timeout_seconds=11,
        )
    )

    assert response.text == '{"result":"ok"}'
    assert response.finish_reason == "stop"
    assert response.usage.total_tokens == 15
    assert captured["max_tokens"] == 42
    assert captured["response_format"] == {"type": "json_object"}
    assert captured["timeout"] == 11


def test_anthropic_provider_normalizes_response(monkeypatch):
    captured = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"score": 8}')],
            stop_reason="end_turn",
            usage=SimpleNamespace(input_tokens=12, output_tokens=7),
        )

    fake_client = SimpleNamespace(messages=SimpleNamespace(create=fake_create))
    monkeypatch.setattr(
        "prompt_hardener.llm.providers.anthropic_client.get_client",
        lambda: fake_client,
    )

    response = AnthropicProvider().generate(
        LLMRequest(
            provider="claude",
            model="claude-sonnet",
            messages=[LLMMessage(role="user", content="hello")],
            system_prompt="system",
            timeout_seconds=9,
        )
    )

    assert response.text == '{"score": 8}'
    assert response.finish_reason == "end_turn"
    assert response.usage.input_tokens == 12
    assert captured["system"] == "system"
    assert captured["timeout"] == 9


def test_bedrock_provider_uses_invoke_model_by_default(monkeypatch):
    fake_body = SimpleNamespace(
        read=lambda: json.dumps(
            {
                "content": [{"text": '{"ok":true}'}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
            }
        )
    )
    fake_client = SimpleNamespace(
        invoke_model=lambda **kwargs: {
            "body": fake_body,
            "kwargs": kwargs,
        }
    )
    monkeypatch.setattr(BedrockProvider, "_make_client", lambda self, request: fake_client)

    response = BedrockProvider().generate(
        LLMRequest(
            provider="bedrock",
            model="anthropic.claude",
            messages=[LLMMessage(role="user", content="hello")],
        )
    )

    assert response.text == '{"ok":true}'
    assert response.finish_reason == "end_turn"
    assert response.usage.total_tokens == 5


def test_bedrock_provider_uses_converse_when_system_prompt_present(monkeypatch):
    captured = {}

    def fake_converse(**kwargs):
        captured.update(kwargs)
        return {
            "output": {"message": {"content": [{"text": "hello"}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 4, "outputTokens": 3, "totalTokens": 7},
        }

    fake_client = SimpleNamespace(converse=fake_converse)
    monkeypatch.setattr(BedrockProvider, "_make_client", lambda self, request: fake_client)

    response = BedrockProvider().generate(
        LLMRequest(
            provider="bedrock",
            model="anthropic.claude",
            system_prompt="system",
            messages=[LLMMessage(role="user", content="hello")],
            max_output_tokens=25,
        )
    )

    assert response.text == "hello"
    assert response.usage.total_tokens == 7
    assert captured["system"] == [{"text": "system"}]
    assert captured["inferenceConfig"]["maxTokens"] == 25


def test_legacy_eval_wrapper_returns_structured_payload(monkeypatch):
    class _FakeClient:
        def generate_json(self, request):
            assert request.provider == "openai"
            assert request.response_format == "json"
            return LLMResponse(
                text='{"score": 9}',
                provider="openai",
                model="gpt-4o-mini",
                structured={"score": 9},
            )

    monkeypatch.setattr("prompt_hardener.llm_client._CLIENT", _FakeClient())
    prompt = PromptInput(
        mode="chat",
        messages=[{"role": "system", "content": "You are helpful"}],
        messages_format="openai",
    )

    result = call_llm_api_for_eval(
        "openai",
        "gpt-4o-mini",
        "sys",
        "criteria message",
        "criteria",
        prompt,
    )

    assert result == {"score": 9}


def test_legacy_attack_completion_wrapper_uses_message_request(monkeypatch):
    captured = {}

    class _FakeClient:
        def generate(self, request):
            captured["request"] = request
            return LLMResponse(text="done", provider=request.provider, model=request.model)

    monkeypatch.setattr("prompt_hardener.llm_client._CLIENT", _FakeClient())

    result = call_llm_api_for_attack_completion(
        "openai",
        "gpt-4o-mini",
        "raw prompt",
    )

    assert result == "done"
    assert captured["request"].messages[0].role == "user"
    assert captured["request"].messages[0].content == "raw prompt"
