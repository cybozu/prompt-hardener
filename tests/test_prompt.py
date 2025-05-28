import json
import tempfile
import pytest
from prompt import parse_prompt_input, format_prompt_output
from schema import PromptInput


def write_temp_json(data: dict) -> str:
    f = tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".json")
    json.dump(data, f)
    f.flush()
    return f.name


def write_temp_text(text: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt")
    f.write(text)
    f.flush()
    return f.name


# ---- parse_prompt_input tests ----


def test_parse_openai_chat():
    path = write_temp_json({"messages": [{"role": "user", "content": "Hello"}]})
    prompt = parse_prompt_input(path, input_mode="chat", input_format="openai")
    assert prompt.mode == "chat"
    assert prompt.messages[0]["role"] == "user"


def test_parse_claude_chat():
    path = write_temp_json(
        {"system": "System", "messages": [{"role": "user", "content": "Hi"}]}
    )
    prompt = parse_prompt_input(path, input_mode="chat", input_format="claude")
    assert prompt.system_prompt == "System"
    assert prompt.messages[0]["content"] == "Hi"


def test_parse_claude_chat_with_role_system():
    path = write_temp_json(
        {"system": "System", "messages": [{"role": "system", "content": "Hi"}]}
    )
    with pytest.raises(ValueError, match="does not support 'role: system' in messages"):
        parse_prompt_input(path, input_mode="chat", input_format="claude")


def test_parse_bedrock_chat():
    path = write_temp_json(
        {"system": "Hello", "messages": [{"role": "user", "content": [{"text": "Hi"}]}]}
    )
    prompt = parse_prompt_input(path, input_mode="chat", input_format="bedrock")
    assert prompt.system_prompt == "Hello"
    assert prompt.messages[0]["content"] == "Hi"


def test_parse_bedrock_chat_with_role_system():
    path = write_temp_json(
        {
            "system": "Hello",
            "messages": [{"role": "system", "content": [{"text": "Hi"}]}],
        }
    )
    with pytest.raises(ValueError, match="does not support 'role: system' in messages"):
        parse_prompt_input(path, input_mode="chat", input_format="bedrock")


def test_parse_completion():
    path = write_temp_text("You are a bot.")
    prompt = parse_prompt_input(path, input_mode="completion", input_format="openai")
    assert prompt.mode == "completion"
    assert "bot" in prompt.completion_prompt


def test_parse_invalid_json():
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".json") as f:
        f.write("{ invalid json }")
        f.flush()
        path = f.name

    with pytest.raises(ValueError, match="Failed to parse prompt input"):
        parse_prompt_input(path, input_mode="chat", input_format="openai")


def test_parse_missing_messages_key():
    path = write_temp_json({"not_messages": []})
    with pytest.raises(ValueError, match="missing 'messages' field"):
        parse_prompt_input(path, input_mode="chat", input_format="openai")


def test_parse_bedrock_wrong_content_structure():
    path = write_temp_json({"messages": [{"role": "user", "content": "not a list"}]})
    prompt = parse_prompt_input(path, input_mode="chat", input_format="bedrock")
    assert prompt.messages[0]["content"] == ""


def test_parse_invalid_completion_prompt():
    path = write_temp_text("")
    with pytest.raises(ValueError, match="must be a non-empty string"):
        parse_prompt_input(path, input_mode="completion", input_format="openai")


# ---- format_prompt_output tests ----


def test_format_openai_chat():
    prompt = PromptInput(
        mode="chat",
        messages=[{"role": "user", "content": "Hi"}],
        messages_format="openai",
    )
    result = format_prompt_output(prompt)
    assert result["messages"][0]["role"] == "user"


def test_format_claude_chat():
    prompt = PromptInput(
        mode="chat",
        messages=[{"role": "user", "content": "Hi"}],
        messages_format="claude",
        system_prompt="Hello",
    )
    result = format_prompt_output(prompt)
    assert result["system"] == "Hello"
    assert result["messages"][0]["content"] == "Hi"


def test_format_bedrock_chat():
    prompt = PromptInput(
        mode="chat",
        messages=[{"role": "user", "content": "Hi"}],
        messages_format="bedrock",
        system_prompt="System",
    )
    result = format_prompt_output(prompt)
    assert result["system"] == "System"
    assert result["messages"][0]["content"][0]["text"] == "Hi"


def test_format_completion():
    prompt = PromptInput(mode="completion", completion_prompt="Generate a poem.")
    result = format_prompt_output(prompt)
    assert result["prompt"].startswith("Generate")


def test_format_invalid_mode():
    prompt = PromptInput(mode="invalid", messages=[])
    with pytest.raises(ValueError, match="Unsupported prompt mode"):
        format_prompt_output(prompt)


def test_format_missing_messages():
    prompt = PromptInput(mode="chat", messages=None)
    with pytest.raises(ValueError, match="Expected 'messages' to be a list"):
        format_prompt_output(prompt)


def test_format_invalid_completion_prompt():
    prompt = PromptInput(mode="completion", completion_prompt="")
    with pytest.raises(
        ValueError,
        match="Expected 'completion_prompt' to be a non-empty string for completion mode.",
    ):
        format_prompt_output(prompt)
