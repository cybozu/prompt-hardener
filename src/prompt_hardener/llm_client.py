import json
from typing import Any, Dict, List, Optional, Union

from prompt_hardener.llm import LLMClient, LLMMessage, LLMRequest
from prompt_hardener.llm.providers.anthropic_client import get_client as get_claude_client
from prompt_hardener.llm.providers.openai_client import get_client as get_openai_client
from prompt_hardener.schema import PromptInput
from prompt_hardener.utils import extract_json_block

_CLIENT = LLMClient()


def _legacy_client() -> LLMClient:
    return _CLIENT


# --- Message builders ---


def build_openai_messages_for_eval(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: PromptInput,
) -> List[Dict[str, str]]:
    if target_prompt.mode == "chat":
        prompt_block = ""
        if target_prompt.messages_format == "openai":
            prompt_block = json.dumps(
                {"messages": target_prompt.messages}, ensure_ascii=False, indent=2
            )
        elif target_prompt.messages_format in ("claude", "bedrock"):
            prompt_block = json.dumps(
                {
                    "system": target_prompt.system_prompt,
                    "messages": target_prompt.messages,
                },
                ensure_ascii=False,
                indent=2,
            )
    elif target_prompt.mode == "completion":
        prompt_block = target_prompt.completion_prompt
    else:
        raise ValueError(f"Unsupported mode: {target_prompt.mode}")

    user_instruction = (
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please evaluate the above according to the criteria and respond in JSON."
    )
    return [
        {"role": "system", "content": system_message.strip()},
        {
            "role": "system",
            "content": f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}",
        },
        {"role": "user", "content": user_instruction.strip()},
    ]


def build_openai_messages_for_improve(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: PromptInput,
) -> List[Dict[str, str]]:
    if target_prompt.mode == "chat":
        prompt_block = ""
        if target_prompt.messages_format == "openai":
            prompt_block = json.dumps(
                {"messages": target_prompt.messages}, ensure_ascii=False, indent=2
            )
        elif target_prompt.messages_format in ("claude", "bedrock"):
            prompt_block = json.dumps(
                {
                    "system": target_prompt.system_prompt,
                    "messages": target_prompt.messages,
                },
                ensure_ascii=False,
                indent=2,
            )
    elif target_prompt.mode == "completion":
        prompt_block = target_prompt.completion_prompt
    else:
        raise ValueError(f"Unsupported mode: {target_prompt.mode}")

    user_instruction = (
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please improve the above according to the criteria and respond in JSON."
    )
    return [
        {"role": "system", "content": system_message.strip()},
        {
            "role": "system",
            "content": f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}",
        },
        {"role": "user", "content": user_instruction.strip()},
    ]


def build_claude_messages_for_eval(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: PromptInput,
) -> List[Dict[str, str]]:
    if target_prompt.mode == "chat":
        prompt_block = ""
        if target_prompt.messages_format == "openai":
            prompt_block = json.dumps(
                {"messages": target_prompt.messages}, ensure_ascii=False, indent=2
            )
        elif target_prompt.messages_format in ("claude", "bedrock"):
            prompt_block = json.dumps(
                {
                    "system": target_prompt.system_prompt,
                    "messages": target_prompt.messages,
                },
                ensure_ascii=False,
                indent=2,
            )
    elif target_prompt.mode == "completion":
        prompt_block = target_prompt.completion_prompt
    else:
        raise ValueError(f"Unsupported mode: {target_prompt.mode}")

    content = (
        f"{system_message.strip()}\n\n"
        f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}\n\n"
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please evaluate the above according to the criteria and respond in valid JSON."
    )
    return [{"role": "user", "content": content.strip()}]


def build_claude_messages_for_improve(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: PromptInput,
) -> List[Dict[str, str]]:
    if target_prompt.mode == "chat":
        prompt_block = ""
        if target_prompt.messages_format == "openai":
            prompt_block = json.dumps(
                {"messages": target_prompt.messages}, ensure_ascii=False, indent=2
            )
        elif target_prompt.messages_format in ("claude", "bedrock"):
            prompt_block = json.dumps(
                {
                    "system": target_prompt.system_prompt,
                    "messages": target_prompt.messages,
                },
                ensure_ascii=False,
                indent=2,
            )
    elif target_prompt.mode == "completion":
        prompt_block = target_prompt.completion_prompt
    else:
        raise ValueError(f"Unsupported mode: {target_prompt.mode}")

    content = (
        f"{system_message.strip()}\n\n"
        f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}\n\n"
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please improve the above according to the criteria and respond in valid JSON."
    )
    return [{"role": "user", "content": content.strip()}]


def _to_request(
    api_mode: str,
    model: str,
    messages: List[Dict[str, Any]],
    *,
    system_message: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    response_format: Optional[str] = None,
    tools: Optional[List[dict]] = None,
    tool_choice: Optional[str] = None,
    stop: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> LLMRequest:
    return LLMRequest(
        provider=api_mode,
        model=model,
        messages=[LLMMessage(role=m["role"], content=m.get("content")) for m in messages],
        system_prompt=system_message,
        temperature=temperature,
        max_output_tokens=max_tokens,
        response_format=response_format,
        aws_region=aws_region,
        aws_profile=aws_profile,
        tools=tools,
        tool_choice=tool_choice,
        stop=stop,
        metadata=metadata,
    )


# --- Compatibility wrappers over prompt_hardener.llm ---


def call_llm_api_for_eval(
    api_mode: str,
    model_name: str,
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: PromptInput,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> Union[List[Dict[str, str]], str]:
    try:
        if api_mode == "openai":
            messages = build_openai_messages_for_eval(
                system_message, criteria_message, criteria, target_prompt
            )
        elif api_mode in ("claude", "bedrock"):
            messages = build_claude_messages_for_eval(
                system_message, criteria_message, criteria, target_prompt
            )
        else:
            raise ValueError(f"Unsupported api_mode: {api_mode}")

        response = _legacy_client().generate_json(
            _to_request(
                api_mode,
                model_name,
                messages,
                temperature=0.2,
                max_tokens=1500,
                aws_region=aws_region,
                aws_profile=aws_profile,
                response_format="json",
                metadata={"bedrock_mode": "invoke_model"},
            )
        )
        return response.structured
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model_name}': {e}"
        )


def call_llm_api_for_improve(
    api_mode: str,
    model_name: str,
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: PromptInput,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        if api_mode == "openai":
            messages = build_openai_messages_for_improve(
                system_message, criteria_message, criteria, target_prompt
            )
        elif api_mode in ("claude", "bedrock"):
            messages = build_claude_messages_for_improve(
                system_message, criteria_message, criteria, target_prompt
            )
        else:
            raise ValueError(f"Unsupported api_mode: {api_mode}")

        response = _legacy_client().generate_json(
            _to_request(
                api_mode,
                model_name,
                messages,
                temperature=0.2,
                max_tokens=1500,
                aws_region=aws_region,
                aws_profile=aws_profile,
                response_format="json",
                metadata={"bedrock_mode": "invoke_model"},
            )
        )
        return response.structured
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model_name}': {e}"
        )


def call_llm_api_for_payload_injection(
    api_mode: str,
    model: str,
    messages: List[Dict[str, str]],
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> str:
    try:
        response = _legacy_client().generate(
            _to_request(
                api_mode,
                model,
                messages,
                temperature=0.2,
                max_tokens=1024,
                aws_region=aws_region,
                aws_profile=aws_profile,
                metadata={"bedrock_mode": "invoke_model"},
            )
        )
        return response.text
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model}': {e}"
        )


def call_llm_api_for_attack_completion(
    api_mode: str,
    model: str,
    prompt: str,
    temperature: float = 0.2,
    max_tokens: int = 1024,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> str:
    try:
        response = _legacy_client().generate(
            _to_request(
                api_mode,
                model,
                [{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                aws_region=aws_region,
                aws_profile=aws_profile,
                metadata={"bedrock_mode": "converse"},
            )
        )
        return response.text.strip()
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} completion API with model '{model}': {e}"
        )


def call_llm_api_for_attack_chat(
    api_mode: str,
    model: str,
    system_message: Optional[str] = None,
    messages: List[Dict[str, str]] = [],
    tools: Optional[List[dict]] = None,
    tool_choice: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 1024,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> str:
    try:
        response = _legacy_client().generate(
            _to_request(
                api_mode,
                model,
                messages,
                system_message=system_message,
                temperature=temperature,
                max_tokens=max_tokens,
                aws_region=aws_region,
                aws_profile=aws_profile,
                tools=tools,
                tool_choice=tool_choice,
                metadata={"bedrock_mode": "converse"},
            )
        )
        return response.text
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model}': {e}"
        )


def call_llm_api_for_judge(
    api_mode: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float = 0.0,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> str:
    try:
        response = _legacy_client().generate(
            _to_request(
                api_mode,
                model,
                messages,
                temperature=temperature,
                max_tokens=512,
                aws_region=aws_region,
                aws_profile=aws_profile,
                metadata={"bedrock_mode": "invoke_model"},
            )
        )
        return response.text
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model}': {e}"
        )


def parse_json_response(text: str) -> Dict[str, Any]:
    """Temporary generic helper for legacy callers expecting parsed JSON."""
    return extract_json_block(text)
