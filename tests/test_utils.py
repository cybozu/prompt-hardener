import pytest
from utils import extract_json_block, to_bedrock_message_format

# Test cases for extract_json_block function


def test_valid_chat_json_block():
    text = """
    {
        "messages": [
            {"role": "system", "content": "Hello"},
            {"role": "user", "content": "Hi"}
        ]
    }
    """
    result = extract_json_block(text)
    print(result)
    assert isinstance(result, dict)
    assert "messages" in result
    assert result["messages"][0]["role"] == "system"
    assert result["messages"][1]["content"] == "Hi"


def test_valid_completion_prompt_block():
    text = '{"prompt": "You are a helpful assistant."}'
    result = extract_json_block(text)
    assert isinstance(result, dict)
    assert "prompt" in result
    assert result["prompt"].startswith("You are a helpful")


def test_chat_block_with_extra_wrapping():
    text = """
    Sure, here is the result:
    ```json
    {
        "messages": [
            {"role": "assistant", "content": "All good"}
        ]
    }
    ```
    Let me know if you need more help.
    """
    result = extract_json_block(text)
    assert isinstance(result, dict)
    assert "messages" in result
    assert result["messages"][0]["role"] == "assistant"
    assert "All good" in result["messages"][0]["content"]


def test_malformed_json_raises_error():
    text = """
    ```json
    {
        "messages": [
            {"role": "system", "content": "Hello"
        ]
    }
    ```"""
    with pytest.raises(ValueError, match="Failed to extract JSON*"):
        extract_json_block(text)


def test_no_json_block_found():
    text = """
    This text does not contain any valid JSON.
    """
    with pytest.raises(
        ValueError, match="No valid JSON block found in the input text."
    ):
        extract_json_block(text)


def test_embedded_json_block():
    text = """
    Here is some text before the JSON:
    ```json
    {
        "key": "value",
        "list": [1, 2, 3]
    }
    ```
    And some text after the JSON.
    """
    result = extract_json_block(text)
    assert isinstance(result, dict)
    assert result["key"] == "value"
    assert result["list"] == [1, 2, 3]


def test_new_line_in_string():
    text = """
    {
        "system": "This is 
a system message.",
        "messages": [
            {"role": "user", "content": "Hello World"}
        ]
    }
    """
    result = extract_json_block(text)
    assert isinstance(result, dict)
    assert "system" in result
    assert result["system"] == "This is a system message."


# Test cases for to_bedrock_message_format function


def test_string_content_is_wrapped_correctly():
    messages = [{"role": "user", "content": "Hello, world!"}]
    expected = [{"role": "user", "content": [{"text": "Hello, world!"}]}]
    assert to_bedrock_message_format(messages) == expected


def test_already_wrapped_content_is_unchanged():
    messages = [{"role": "assistant", "content": [{"text": "Hi there!"}]}]
    assert to_bedrock_message_format(messages) == messages


def test_multiple_messages_mixed_formats():
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": [{"text": "What's the weather like?"}]},
    ]
    expected = [
        {"role": "system", "content": [{"text": "You are a helpful assistant."}]},
        {"role": "user", "content": [{"text": "What's the weather like?"}]},
    ]
    assert to_bedrock_message_format(messages) == expected


def test_invalid_content_type_raises_error():
    messages = [
        {"role": "user", "content": 123}  # Invalid type
    ]
    with pytest.raises(TypeError):
        to_bedrock_message_format(messages)
