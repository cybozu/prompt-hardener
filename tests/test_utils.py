import pytest
from src.utils import extract_json_block, to_bedrock_message_format

# Test cases for extract_json_block function

def test_valid_json_block_with_key():
    text = '''
    {
        "messages": [
            {"role": "system", "content": "Hello"},
            {"role": "user", "content": "Hi"}
        ]
    }
    '''
    result = extract_json_block(text)
    assert isinstance(result, list)
    assert result[0]["role"] == "system"
    assert result[1]["content"] == "Hi"

def test_valid_json_block_with_extra_text():
    text = '''
    Sure, here is the result:
    ```json
    {
        "messages": [
            {"role": "assistant", "content": "All good"}
        ]
    }
    ```
    Let me know if you need more.
    '''
    result = extract_json_block(text)
    assert isinstance(result, list)
    assert result[0]["role"] == "assistant"

def test_missing_key():
    text = '''
    ```json
    {
        "not_messages": []
    }
    ```'''
    with pytest.raises(ValueError, match="Key 'messages' not found"):
        extract_json_block(text)

def test_malformed_json():
    text = '''
    ```json
    {
        "messages": [
            {"role": "system", "content": "Hello"
        ]
    }
    ```'''
    with pytest.raises(ValueError, match="Failed to extract JSON"):
        extract_json_block(text)

# Test cases for to_bedrock_message_format function

def test_string_content_is_wrapped_correctly():
    messages = [
        {"role": "user", "content": "Hello, world!"}
    ]
    expected = [
        {
            "role": "user",
            "content": [{"text": "Hello, world!"}]
        }
    ]
    assert to_bedrock_message_format(messages) == expected

def test_already_wrapped_content_is_unchanged():
    messages = [
        {
            "role": "assistant",
            "content": [{"text": "Hi there!"}]
        }
    ]
    assert to_bedrock_message_format(messages) == messages

def test_multiple_messages_mixed_formats():
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": [{"text": "What's the weather like?"}]}
    ]
    expected = [
        {
            "role": "system",
            "content": [{"text": "You are a helpful assistant."}]
        },
        {
            "role": "user",
            "content": [{"text": "What's the weather like?"}]
        }
    ]
    assert to_bedrock_message_format(messages) == expected

def test_invalid_content_type_raises_error():
    messages = [
        {"role": "user", "content": 123}  # Invalid type
    ]
    with pytest.raises(TypeError):
        to_bedrock_message_format(messages)