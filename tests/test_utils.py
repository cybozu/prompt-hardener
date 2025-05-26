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
    result = extract_json_block(text, key="messages")
    assert isinstance(result, list)
    assert result[0]["role"] == "system"
    assert result[1]["content"] == "Hi"


def test_valid_completion_prompt_block():
    text = '{"prompt": "You are a helpful assistant."}'
    result = extract_json_block(text, key="prompt")
    assert isinstance(result, str)
    assert result.startswith("You are a helpful")


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
    result = extract_json_block(text, key="messages")
    assert isinstance(result, list)
    assert result[0]["role"] == "assistant"
    assert "All good" in result[0]["content"]


def test_missing_key_raises_error():
    text = """
    ```json
    {
        "not_messages": []
    }
    ```
    """
    with pytest.raises(ValueError, match="Key 'messages' not found"):
        extract_json_block(text, key="messages")


def test_malformed_json_raises_error():
    text = """
    ```json
    {
        "messages": [
            {"role": "system", "content": "Hello"
        ]
    }
    ```"""
    with pytest.raises(ValueError, match="Failed to extract JSON"):
        extract_json_block(text, key="messages")


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
