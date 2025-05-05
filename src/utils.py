import json
from typing import List, Dict
from openai import OpenAI

client = OpenAI()


def build_openai_messages(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: List[Dict[str, str]],
    json_response: bool = True
) -> List[Dict[str, str]]:
    """
    Construct chat messages for OpenAI's Chat Completion API.
    `target_prompt` is a list of messages (Chat Completion format).
    """
    # Embed the serialized prompt into user instruction
    prompt_block = json.dumps(target_prompt, ensure_ascii=False, indent=2)
    user_instruction = (
        f"The target prompt is:\n{prompt_block}\n\n"
        f"Please evaluate or improve the above according to the criteria and respond in JSON."
        if json_response else
        f"The target prompt is:\n{prompt_block}"
    )

    return [
        {"role": "system", "content": system_message.strip()},
        {"role": "system", "content": f"The evaluation criteria are:\n{criteria_message.strip()}\n{criteria.strip()}"},
        {"role": "user", "content": user_instruction.strip()},
    ]


def call_openai_api(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: List[Dict[str, str]],
    model_name: str,
    json_response: bool = True
) -> List[Dict[str, str]] | str:
    """
    Call the OpenAI Chat Completion API with the given structured prompt.
    Returns a parsed JSON object or raw string depending on `json_response`.
    """
    try:
        messages = build_openai_messages(
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

        completion = client.chat.completions.create(**kwargs)
        content = completion.choices[0].message.content

        return json.loads(content) if json_response else content

    except Exception as e:
        raise ValueError(
            f"Error: Failed to call OpenAI API with model '{model_name}': {e}"
        )
