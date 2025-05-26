from typing import List, Dict, Union, Any
import re
import json


def validate_chat_completion_format(prompt: List[Dict[str, str]]) -> None:
    """
    Validates the format of a chat completion prompt.
    Each entry must be a JSON object with 'role' and 'content' keys.
    The 'role' must be one of 'system', 'user', or 'assistant'.
    The 'content' must be a string.
    """
    if not isinstance(prompt, list):
        raise ValueError("Prompt must be a JSON array.")
    for entry in prompt:
        if not isinstance(entry, dict):
            raise ValueError("Each entry must be a JSON object.")
        if "role" not in entry or "content" not in entry:
            raise ValueError("Each message must contain 'role' and 'content' keys.")
        if entry["role"] not in ("system", "user", "assistant"):
            raise ValueError(f"Invalid role: {entry['role']}")
        if not isinstance(entry["content"], str):
            raise ValueError("Message 'content' must be a string.")


def extract_json_block(text: str, key: str = "messages") -> Union[List[Dict[str, str]], str]:
    """
    Extracts a JSON object from the text and returns the value of the specified key.
    The text may contain markdown formatting or extraneous explanation text.

    Supports:
    - key="messages" -> expects value to be List[Dict[str, str]]
    - key="prompt"   -> expects value to be str
    """
    try:
        # Remove markdown code fences
        text = re.sub(r"```(?:json)?", "", text).strip()

        # Attempt direct JSON parse
        try:
            full_data = json.loads(text)
            if key not in full_data:
                raise ValueError(f"Key '{key}' not found in JSON.")
            return full_data[key]
        except json.JSONDecodeError:
            pass

        # Search for embedded JSON object
        matches = re.findall(r"{[\s\S]*}", text)
        for candidate in matches:
            try:
                data = json.loads(candidate)
                if key in data:
                    return data[key]
            except json.JSONDecodeError:
                continue

        raise ValueError(f"Key '{key}' not found in any valid JSON block.")
    
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Failed to extract JSON: {e}")

def to_bedrock_message_format(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Converts messages to Bedrock Converse API format.
    Bedrock expects each message's `content` to be a list of single-key dicts like [{"text": "..."}]
    """
    converted = []
    for m in messages:
        content = m["content"]

        if isinstance(content, str):
            # ✅ OpenAI-style str → Bedrock-style [{"text": "..."}]
            content = [{"text": content}]
        elif isinstance(content, list):
            # ✅ Validate each content block is Bedrock-style (e.g., {"text": "..."})
            for block in content:
                if not isinstance(block, dict) or len(block) != 1:
                    raise TypeError(
                        "Each content item must be a dict with exactly one key (e.g., {'text': '...'})"
                    )
                if not any(
                    k in block
                    for k in {
                        "text",
                        "image",
                        "toolUse",
                        "toolResult",
                        "document",
                        "video",
                    }
                ):
                    raise ValueError(f"Unsupported content type: {block}")
        else:
            raise TypeError(f"Invalid content type: {type(content)}")

        converted.append({"role": m["role"], "content": content})

    return converted
