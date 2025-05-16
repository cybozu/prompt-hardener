import json
from typing import List, Dict, Union, Optional
from openai import OpenAI
from anthropic import Anthropic

openai_client = OpenAI()
claude_client = Anthropic()

# --- Message builders ---


def build_openai_messages_for_eval(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: List[Dict[str, str]],
    json_response: bool = True,
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
    user_instruction = (
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please evaluate the above according to the criteria and respond in JSON."
        if json_response
        else f"The target prompt is:\n{prompt_block}"
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
    json_response: bool = True,
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
    user_instruction = (
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please improve the above according to the criteria and respond in JSON."
        if json_response
        else f"The target prompt is:\n{prompt_block}"
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
    json_response: bool = True,
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
    content = (
        f"{system_message.strip()}\n\n"
        f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}\n\n"
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please evaluate the above according to the criteria and respond in JSON."
        if json_response
        else f"{system_message.strip()}\n\n{prompt_block}"
    )
    return [{"role": "user", "content": content.strip()}]


def build_claude_messages_for_improve(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: List[Dict[str, str]],
    json_response: bool = True,
) -> List[Dict[str, str]]:
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
    content = (
        f"{system_message.strip()}\n\n"
        f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}\n\n"
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please improve the above according to the criteria and respond in JSON."
        if json_response
        else f"{system_message.strip()}\n\n{prompt_block}"
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
    json_response: bool = True,
) -> Union[List[Dict[str, str]], str]:
    try:
        if api_mode == "openai":
            messages = build_openai_messages_for_eval(
                system_message, criteria_message, criteria, target_prompt, json_response
            )
            kwargs = {
                "model": model_name,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
            }
            if json_response:
                kwargs["response_format"] = {"type": "json_object"}
            completion = openai_client.chat.completions.create(**kwargs)
            content = completion.choices[0].message.content
            return json.loads(content) if json_response else content

        elif api_mode == "claude":
            messages = build_claude_messages_for_eval(
                system_message, criteria_message, criteria, target_prompt, json_response
            )
            completion = claude_client.messages.create(
                model=model_name, messages=messages, max_tokens=1500, temperature=0.2
            )
            content = completion.content[0].text
            return json.loads(content) if json_response else content

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
    json_response: bool = True,
) -> Union[List[Dict[str, str]], str]:
    try:
        if api_mode == "openai":
            messages = build_openai_messages_for_improve(
                system_message, criteria_message, criteria, target_prompt, json_response
            )
            kwargs = {
                "model": model_name,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
            }
            if json_response:
                kwargs["response_format"] = {"type": "json_object"}
            completion = openai_client.chat.completions.create(**kwargs)
            content = completion.choices[0].message.content
            return json.loads(content) if json_response else content

        elif api_mode == "claude":
            messages = build_claude_messages_for_improve(
                system_message, criteria_message, criteria, target_prompt, json_response
            )
            completion = claude_client.messages.create(
                model=model_name, messages=messages, max_tokens=1500, temperature=0.2
            )
            content = completion.content[0].text
            return json.loads(content) if json_response else content

        else:
            raise ValueError(f"Unsupported API mode: {api_mode}")

    except Exception as e:
        raise ValueError(
            f"Error: Failed to call {api_mode} API with model '{model_name}': {e}"
        )


def call_llm_api_for_attack(
    api_mode: str,
    model: str,
    messages: List[Dict[str, str]],
    tools: Optional[List[dict]] = None,
    tool_choice: Optional[str] = None,
    temperature: float = 0.2,
) -> str:
    if api_mode == "openai":
        kwargs = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 1024,
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

    else:
        raise ValueError(f"Unsupported API mode: {api_mode}")


def call_llm_api_for_judge(
    api_mode: str, model: str, messages: List[Dict[str, str]], temperature: float = 0.0
) -> str:
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

    else:
        raise ValueError(f"Unsupported API mode: {api_mode}")
