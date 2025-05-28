import os
import json
import requests
from typing import List, Dict, Union, Optional, Any
from openai import OpenAI
from anthropic import Anthropic
import boto3
from utils import extract_json_block, to_bedrock_message_format
from schema import PromptInput

openai_client = OpenAI()
claude_client = Anthropic()

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


# --- API Callers ---


def call_llm_api_for_eval(
    api_mode: str,
    model_name: str,
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: PromptInput,
    aws_region: Optional[str] = None,
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

        if api_mode == "openai":
            completion = openai_client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=0.2,
                max_tokens=1500,
                response_format={"type": "json_object"},
            )
            content = completion.choices[0].message.content
        elif api_mode == "claude":
            completion = claude_client.messages.create(
                model=model_name,
                messages=messages,
                temperature=0.2,
                max_tokens=1500,
            )
            content = completion.content[0].text
        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            json_data = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
            }
            response = bedrock_client.invoke_model(
                modelId=model_name,
                body=json.dumps(json_data),
                contentType="application/json",
                accept="application/json",
            )
            response_body = json.loads(response.get("body").read())
            content = response_body["content"][0]["text"]
        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")

        return json.loads(content)

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

        if api_mode == "openai":
            completion = openai_client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=0.2,
                max_tokens=1500,
                response_format={"type": "json_object"},
            )
            content = completion.choices[0].message.content

        elif api_mode == "claude":
            completion = claude_client.messages.create(
                model=model_name,
                messages=messages,
                temperature=0.2,
                max_tokens=1500,
            )
            content = completion.content[0].text

        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            json_data = {
                "anthropic_version": "bedrock-2023-05-31",
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
            }
            response = bedrock_client.invoke_model(
                modelId=model_name,
                body=json.dumps(json_data),
                contentType="application/json",
                accept="application/json",
            )
            response_body = json.loads(response.get("body").read())
            content = response_body["content"][0]["text"]
        messages = extract_json_block(content)
        return messages

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


def call_llm_api_for_attack_completion(
    api_mode: str,
    model: str,
    prompt: str,
    temperature: float = 0.2,
    max_tokens: int = 1024,
    aws_region: Optional[str] = None,
) -> str:
    try:
        if api_mode == "openai":
            response = requests.post(
                "https://api.openai.com/v1/completions",
                headers={
                    "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY')}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "prompt": prompt,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
            )
            choices = response.json().get("choices", [])
            if len(choices) > 0:
                return choices[0].get("text", "").strip()
            else:
                return ""

        elif api_mode == "claude":
            kwargs = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 1024,
            }
            response = claude_client.messages.create(**kwargs)
            if len(response.content) > 0:
                return response.content[0].text.strip()
            else:
                return ""

        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            kwargs = {
                "modelId": model,
                "messages": [{"role": "user", "content": [{"text": prompt}]}],
                "inferenceConfig": {
                    "temperature": temperature,
                    "maxTokens": max_tokens,
                },
            }
            response = bedrock_client.converse(**kwargs)
            if len(response["output"]["message"]["content"]) > 0:
                return response["output"]["message"]["content"][0]["text"]
            else:
                return ""

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")

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
) -> str:
    try:
        if api_mode == "openai":
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if tools:
                kwargs["tools"] = tools
            response = openai_client.chat.completions.create(**kwargs)
            if len(response.choices) > 0 and response.choices[0].message:
                return response.choices[0].message.content
            else:
                return ""

        elif api_mode == "claude":
            kwargs = {
                "model": model,
                "system": system_message,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if tools:
                kwargs["tools"] = tools
            response = claude_client.messages.create(**kwargs)
            if len(response.content) > 0:
                return response.content[0].text.strip()
            else:
                return ""

        elif api_mode == "bedrock":
            bedrock_client = boto3.client("bedrock-runtime", region_name=aws_region)
            messages = to_bedrock_message_format(messages)
            kwargs = {
                "modelId": model,
                "system": [{"text": system_message}],
                "messages": messages,
                "inferenceConfig": {
                    "temperature": temperature,
                    "maxTokens": max_tokens,
                },
            }
            if tools:
                kwargs["toolConfig"] = tools
            response = bedrock_client.converse(**kwargs)
            if len(response["output"]["message"]["content"]) > 0:
                return response["output"]["message"]["content"][0]["text"]
            else:
                return ""

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
            if len(response_content["content"]) == 0:
                return ""
            return response_content["content"][0]["text"].strip()

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")
    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model}': {e}"
        )
