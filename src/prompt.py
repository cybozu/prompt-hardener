import json
from typing import Literal
from pathlib import Path
from schema import PromptInput


def parse_prompt_input(path: str, input_mode: str, input_format: str) -> PromptInput:
    """
    Parses a prompt input file and returns a PromptInput object.
    :param path: Path to the input file.
    :param input_mode: Mode of the prompt, either "chat" or "completion".
    :param input_format: Format of the input, either "openai", "claude", or "bedrock".
    :return: PromptInput object containing the parsed prompt.
    """
    try:
        if input_mode == "chat":
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)

            if input_format == "openai":
                if not isinstance(raw, dict) or "messages" not in raw:
                    raise ValueError(
                        "Invalid OpenAI chat format: missing 'messages' field"
                    )
                return PromptInput(
                    mode="chat", messages=raw["messages"], messages_format="openai"
                )

            elif input_format == "claude":
                if not isinstance(raw, dict) or "messages" not in raw:
                    raise ValueError(
                        "Invalid Claude chat format: missing 'messages' field"
                    )
                # Check for role: system in messages
                if any(m.get("role") == "system" for m in raw["messages"]):
                    raise ValueError(
                        "Claude chat format does not support 'role: system' in messages."
                    )
                return PromptInput(
                    mode="chat",
                    messages=raw["messages"],
                    messages_format="claude",
                    system_prompt=raw.get("system"),
                )

            elif input_format == "bedrock":
                if not isinstance(raw, dict) or "messages" not in raw:
                    raise ValueError(
                        "Invalid Bedrock chat format: missing 'messages' field"
                    )
                # Check for role: system in messages
                if any(m.get("role") == "system" for m in raw["messages"]):
                    raise ValueError(
                        "Bedrock chat format does not support 'role: system' in messages."
                    )
                return PromptInput(
                    mode="chat",
                    messages=[
                        {
                            "role": m["role"],
                            "content": m["content"][0]["text"]
                            if isinstance(m.get("content"), list)
                            and m["content"]
                            and "text" in m["content"][0]
                            else "",
                        }
                        for m in raw["messages"]
                    ],
                    messages_format="bedrock",
                    system_prompt=raw.get("system"),
                )

        elif input_mode == "completion":
            with open(path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            if not isinstance(raw, str) or not raw:
                raise ValueError(
                    "Invalid completion prompt format: must be a non-empty string"
                )
            return PromptInput(mode="completion", completion_prompt=raw)

        raise ValueError(
            f"Unsupported input_mode={input_mode}, input_format={input_format}"
        )

    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        raise ValueError(f"Failed to parse prompt input from {path}: {e}")


def format_prompt_output(prompt: PromptInput) -> dict:
    """
    Formats a PromptInput object back into its original provider-specific format.
    :param prompt: PromptInput object containing the normalized internal structure.
    :return: Dictionary in the format expected by the specified input provider.
    """
    if prompt.mode == "chat":
        if not isinstance(prompt.messages, list):
            raise ValueError("Expected 'messages' to be a list for chat mode.")

        if prompt.messages_format == "openai":
            return {"messages": prompt.messages}

        elif prompt.messages_format == "claude":
            return {
                "system": prompt.system_prompt or "",
                "messages": prompt.messages,
            }

        elif prompt.messages_format == "bedrock":
            return {
                "system": prompt.system_prompt or "",
                "messages": [
                    {
                        "role": m["role"],
                        "content": [{"text": m["content"]}]
                        if isinstance(m.get("content"), str)
                        else [],
                    }
                    for m in prompt.messages
                ],
            }

    elif prompt.mode == "completion":
        if (
            not isinstance(prompt.completion_prompt, str)
            or not prompt.completion_prompt.strip()
        ):
            raise ValueError(
                "Expected 'completion_prompt' to be a non-empty string for completion mode."
            )
        return {"prompt": prompt.completion_prompt}

    else:
        raise ValueError(f"Unsupported prompt mode: {prompt.mode}")


def write_prompt_output(
    output_path: str,
    prompt: PromptInput,
    input_mode: Literal["chat", "completion"],
    output_format: Literal["openai", "claude", "bedrock"],
) -> None:
    """
    Writes a PromptInput object to a file using the specified provider format.

    :param output_path: Path to the output file.
    :param prompt: Normalized internal PromptInput object.
    :param input_mode: Mode of the prompt, either "chat" or "completion".
    :param output_format: One of 'openai', 'claude', 'bedrock'.
    """
    data = format_prompt_output(prompt)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    if input_mode == "chat":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    elif input_mode == "completion":
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(data["prompt"].strip())
    else:
        raise ValueError(f"Unsupported input_mode={input_mode} for writing output")


def show_prompt(prompt: PromptInput) -> str:
    """
    Format a PromptInput object into a JSON string for display in the report.
    """
    if prompt.mode == "chat":
        if prompt.messages_format == "openai":
            return json.dumps(
                {"messages": prompt.messages, "system": prompt.system_prompt},
                indent=2,
                ensure_ascii=False,
            )
        elif prompt.messages_format in ("claude", "bedrock"):
            # Claude and Bedrock formats do not include system prompt in messages
            return json.dumps(
                {
                    "messages": prompt.messages,
                    "system": prompt.system_prompt,
                },
                indent=2,
                ensure_ascii=False,
            )
        else:
            raise ValueError(f"Unsupported messages format: {prompt.messages_format}")
    elif prompt.mode == "completion":
        return json.dumps(
            {"prompt": prompt.completion_prompt}, indent=2, ensure_ascii=False
        )
    else:
        raise ValueError(f"Unsupported prompt mode: {prompt.mode}")
