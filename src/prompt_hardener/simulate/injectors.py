"""Prompt normalization and payload injection helpers for simulation."""

import re

from prompt_hardener.schema import PromptInput


def normalize_salted_tags_in_prompt(
    prompt: PromptInput, random_tag: str
) -> PromptInput:
    def replace_tags(text: str) -> str:
        text = re.sub(r"<\{RANDOM\}>", f"<{random_tag}>", text)
        text = re.sub(r"</\{RANDOM\}>", f"</{random_tag}>", text)
        text = re.sub(
            r"<(SECURE_PROMPT|securePrompt|secure_prompt|authBlock|AUTHBLOCK)>",
            f"<{random_tag}>",
            text,
        )
        text = re.sub(
            r"</(SECURE_PROMPT|securePrompt|secure_prompt|authBlock|AUTHBLOCK)>",
            f"</{random_tag}>",
            text,
        )
        return text

    if prompt.mode == "chat":
        new_messages = [
            {"role": m["role"], "content": replace_tags(m["content"])}
            for m in (prompt.messages or [])
        ]
        if prompt.messages_format == "openai":
            return PromptInput(
                mode="chat",
                messages=new_messages,
                messages_format=prompt.messages_format,
            )
        if prompt.messages_format in ("claude", "bedrock"):
            return PromptInput(
                mode="chat",
                messages=new_messages,
                messages_format=prompt.messages_format,
                system_prompt=replace_tags(prompt.system_prompt or ""),
            )
    elif prompt.mode == "completion":
        return PromptInput(
            mode="completion",
            completion_prompt=replace_tags(prompt.completion_prompt or ""),
        )
    raise ValueError("Unsupported prompt mode: %s" % prompt.mode)


def normalize_prompt_for_provider(prompt: PromptInput, provider: str) -> PromptInput:
    """Normalize PromptInput into the message layout expected by *provider*."""
    if prompt.mode != "chat":
        return prompt

    messages = list(prompt.messages or [])
    system_parts = []
    if prompt.system_prompt:
        system_parts.append(prompt.system_prompt)

    non_system_messages = []
    for message in messages:
        if message.get("role") == "system" and isinstance(message.get("content"), str):
            system_parts.append(message["content"])
            continue
        non_system_messages.append(message)

    if provider == "openai":
        openai_messages = []
        system_text = "\n\n".join(part for part in system_parts if part)
        if system_text:
            openai_messages.append({"role": "system", "content": system_text})
        openai_messages.extend(non_system_messages)
        return PromptInput(
            mode="chat",
            messages=openai_messages,
            messages_format="openai",
        )

    if provider in ("claude", "bedrock"):
        return PromptInput(
            mode="chat",
            messages=non_system_messages,
            messages_format=provider,
            system_prompt="\n\n".join(part for part in system_parts if part) or None,
        )

    raise ValueError("Unsupported provider: %s" % provider)


def ensure_conversation_starts_with_user(
    prompt: PromptInput,
    provider: str,
    fallback_user_content: str = "Please continue.",
) -> PromptInput:
    """Ensure provider-specific conversation invariants before execution."""
    if prompt.mode != "chat" or provider not in ("claude", "bedrock"):
        return prompt

    messages = list(prompt.messages or [])
    if not messages or messages[0].get("role") != "user":
        messages.insert(0, {"role": "user", "content": fallback_user_content})

    return PromptInput(
        mode="chat",
        messages=messages,
        messages_format=provider,
        system_prompt=prompt.system_prompt,
    )


def inject_as_tool_result(
    prompt: PromptInput, payload: str, tool_name: str = "search"
) -> PromptInput:
    """Inject payload as a synthetic tool result."""
    benign_question = "Can you look up the latest information for me?"

    if prompt.messages_format == "openai":
        messages = list(prompt.messages or [])
        messages.extend(
            [
                {"role": "user", "content": benign_question},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_inject_001",
                            "type": "function",
                            "function": {"name": tool_name, "arguments": "{}"},
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call_inject_001",
                    "content": payload,
                },
            ]
        )
        return PromptInput(
            mode="chat",
            messages=messages,
            messages_format="openai",
        )

    if prompt.messages_format == "claude":
        messages = list(prompt.messages or [])
        messages.extend(
            [
                {"role": "user", "content": benign_question},
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_inject_001",
                            "name": tool_name,
                            "input": {},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_inject_001",
                            "content": payload,
                        }
                    ],
                },
            ]
        )
        return PromptInput(
            mode="chat",
            messages=messages,
            messages_format=prompt.messages_format,
            system_prompt=prompt.system_prompt,
        )

    if prompt.messages_format == "bedrock":
        messages = list(prompt.messages or [])
        messages.extend(
            [
                {"role": "user", "content": benign_question},
                {
                    "role": "assistant",
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "toolu_inject_001",
                                "name": tool_name,
                                "input": {},
                            }
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "toolResult": {
                                "toolUseId": "toolu_inject_001",
                                "content": [{"text": payload}],
                            }
                        }
                    ],
                },
            ]
        )
        return PromptInput(
            mode="chat",
            messages=messages,
            messages_format=prompt.messages_format,
            system_prompt=prompt.system_prompt,
        )

    raise ValueError(
        "Unsupported messages_format for tool_result injection: %s"
        % prompt.messages_format
    )


def inject_as_rag_context(prompt: PromptInput, payload: str) -> PromptInput:
    """Inject payload as retrieved RAG context in a user message."""
    rag_content = (
        "---BEGIN RETRIEVED DOCUMENT---\n"
        "%s\n"
        "---END RETRIEVED DOCUMENT---\n\n"
        "Based on the above document, please answer my question: "
        "What are the key points?"
    ) % payload

    if prompt.messages_format == "openai":
        messages = list(prompt.messages or [])
        messages.append({"role": "user", "content": rag_content})
        return PromptInput(
            mode="chat",
            messages=messages,
            messages_format="openai",
        )

    if prompt.messages_format in ("claude", "bedrock"):
        messages = list(prompt.messages or [])
        messages.append({"role": "user", "content": rag_content})
        return PromptInput(
            mode="chat",
            messages=messages,
            messages_format=prompt.messages_format,
            system_prompt=prompt.system_prompt,
        )

    raise ValueError(
        "Unsupported messages_format for rag_context injection: %s"
        % prompt.messages_format
    )


def inject_as_mcp_response(
    prompt: PromptInput, payload: str, server_name: str = "external_server"
) -> PromptInput:
    """Inject payload as an MCP server response."""
    return inject_as_tool_result(prompt, payload, tool_name="%s__query" % server_name)


def build_prompt_input_with_payload(
    prompt: PromptInput,
    payload: str,
    injection_method: str,
    *,
    tool_name=None,
    server_name=None,
) -> PromptInput:
    if injection_method == "tool_result":
        return inject_as_tool_result(prompt, payload, tool_name or "search")
    if injection_method == "rag_context":
        return inject_as_rag_context(prompt, payload)
    if injection_method == "mcp_response":
        return inject_as_mcp_response(prompt, payload, server_name or "external_server")
    raise ValueError("Unsupported injection_method: %s" % injection_method)
