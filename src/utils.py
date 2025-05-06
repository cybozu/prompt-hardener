from typing import List, Dict


def validate_chat_completion_format(prompt: List[Dict[str, str]]) -> None:
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
