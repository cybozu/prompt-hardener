import json
from typing import List, Dict, Union, Optional
from openai import OpenAI
from anthropic import Anthropic
import boto3
from utils import extract_json_block, to_bedrock_message_format

openai_client = OpenAI()
claude_client = Anthropic()

# --- Message builders ---


def build_openai_messages_for_eval(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
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
    target_prompt: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
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
    target_prompt: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
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
    target_prompt: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
    content = (
        f"{system_message.strip()}\n\n"
        f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}\n\n"
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please improve the above according to the criteria and respond in valid JSON."
    )
    return [{"role": "user", "content": content.strip()}]


# --- API Callers ---


def call_llm_api_for_eval(
    api_mode: str,
    model_name: str,
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: List[Dict[str, str]],
    aws_region: Optional[str] = None,
) -> Union[List[Dict[str, str]], str]:
    try:
        if api_mode == "openai":
            messages = build_openai_messages_for_eval(
                system_message, criteria_message, criteria, target_prompt
            )
            kwargs = {
                "model": model_name,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
                "response_format": {"type": "json_object"},
            }
            completion = openai_client.chat.completions.create(**kwargs)
            content = completion.choices[0].message.content
            return json.loads(content)

        elif api_mode == "claude":
            messages = build_claude_messages_for_eval(
                system_message, criteria_message, criteria, target_prompt
            )
            completion = claude_client.messages.create(
                model=model_name, messages=messages, max_tokens=1500, temperature=0.2
            )
            content = completion.content[0].text
            return json.loads(content)
            
        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            messages = build_claude_messages_for_eval(
                system_message, criteria_message, criteria, target_prompt
            )
            json_data = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
            }
            completion = bedrock_client.invoke_model(
                modelId=model_name,
                body=json.dumps(json_data),
                contentType="application/json",
                accept="application/json",
            )
            response = json.loads(completion.get("body").read())
            content = response["content"][0]["text"]
            print("content", content)
            return json.loads(content)

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")

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
    target_prompt: List[Dict[str, str]],
    aws_region: Optional[str] = None,
) -> Union[List[Dict[str, str]], str]:
    try:
        if api_mode == "openai":
            messages = build_openai_messages_for_improve(
                system_message, criteria_message, criteria, target_prompt
            )
            kwargs = {
                "model": model_name,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
                "response_format": {"type": "json_object"}
            }
            completion = openai_client.chat.completions.create(**kwargs)
            content = completion.choices[0].message.content
            messages = extract_json_block(content, key="messages")
            return messages

        elif api_mode == "claude":
            messages = build_claude_messages_for_improve(
                system_message, criteria_message, criteria, target_prompt
            )
            completion = claude_client.messages.create(
                model=model_name, messages=messages, max_tokens=1500, temperature=0.2
            )
            content = completion.content[0].text
            messages = extract_json_block(content, key="messages")
            return messages

        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            messages = build_claude_messages_for_improve(
                system_message, criteria_message, criteria, target_prompt
            )
            json_data = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
            }
            completion = bedrock_client.invoke_model(
                modelId=model_name,
                body=json.dumps(json_data),
                contentType="application/json",
                accept="application/json",
            )
            response = json.loads(completion.get("body").read())
            content = response["content"][0]["text"]
            print("content", content)
            messages = extract_json_block(content, key="messages")
            return messages

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")

    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model_name}': {e}"
        )

def call_llm_api_for_payload_injection(
    api_mode: str,
    model: str,
    messages: List[Dict[str, str]],
    aws_region: Optional[str] = None,
) -> str:
    try:
        if api_mode == "openai":
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1024,
            }
            response = openai_client.chat.completions.create(**kwargs)
            return response.choices[0].message.content

        elif api_mode == "claude":
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1024,
            }
            response = claude_client.messages.create(**kwargs)
            return response.content[0].text.strip()

        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            json_data = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1024,
            }
            response = bedrock_client.invoke_model(
                modelId=model,
                body=json.dumps(json_data),
                contentType="application/json",
                accept="application/json",
            )
            response_content = json.loads(response.get("body").read())
            return response_content["content"][0]["text"].strip()

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model}': {e}"
        )


def call_llm_api_for_attack(
    api_mode: str,
    model: str,
    messages: List[Dict[str, str]],
    tools: Optional[List[dict]] = None,
    tool_choice: Optional[str] = None,
    temperature: float = 0.2,
    aws_region: Optional[str] = None,
) -> str:
    try:
        if api_mode == "openai":
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": 1024
            }
            if tools:
                kwargs["tools"] = tools
            response = openai_client.chat.completions.create(**kwargs)
            return response.choices[0].message.content

        elif api_mode == "claude":
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": 1024,
            }
            if tools:
                kwargs["tools"] = tools
            response = claude_client.messages.create(**kwargs)
            return response.content[0].text.strip()

        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            messages = to_bedrock_message_format(messages)
            kwargs = {
                "modelId": model,
                "messages": messages,
                "inferenceConfig": {
                    "temperature": temperature,
                    "maxTokens": 1024,
                }
            }
            if tools:
                kwargs["toolConfig"] = tools
            response = bedrock_client.converse(**kwargs)
            return response["output"]["message"]["content"][0]["text"]

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")
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
) -> str:
    try:
        if api_mode == "openai":
            response = openai_client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
            )
            return response.choices[0].message.content

        elif api_mode == "claude":
            response = claude_client.messages.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=512,
            )
            return response.content[0].text.strip()

        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            json_data = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": messages,
                "temperature": temperature,
                "max_tokens": 512,
            }
            response = bedrock_client.invoke_model(
                modelId=model,
                body=json.dumps(json_data),
                contentType="application/json",
                accept="application/json",
            )
            response_content = json.loads(response.get("body").read())
            return response_content["content"][0]["text"].strip()

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model}': {e}"
        )
